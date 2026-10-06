"""ADMX/ADML template parser for policy crosswalk.

Parses ``.admx`` (policy definitions) and ``.adml`` (language resources)
from a ``PolicyDefinitions`` directory to build a registry-path → policy-name
crosswalk.  Used by the baseline-diff feature to map raw registry settings
back to their ADMX policy definitions.

ADMX files are XML with the namespace
``http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions``.

Each ``<policy>`` element carries:
- ``name`` — the policy identifier
- ``class`` — ``"Machine"``, ``"User"``, or ``"Both"``
- ``key`` — the registry key path (relative to HKLM/HKCU)
- ``valueName`` — the registry value name
- ``displayName`` — a ``$(string.xxx)`` reference resolved via ADML

The crosswalk maps ``(key, valueName)`` → policy display name, which lets
the baseline diff convert raw registry identities (e.g.
``Software\\Policies\\Microsoft\\...:NoControlPanel``) back to human-readable
policy names.
"""

from __future__ import annotations

import codecs
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ET

from gpo_lens.model import Side
from gpo_lens.normalize import localname

_ADMX_NS = "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"

_localname = localname

_XML_DECLARATION = re.compile(r"\A<\?xml\s+[^?]*\?>")
_XML_ENCODING = re.compile(r"\s+encoding\s*=\s*(['\"])([^'\"]+)\1")


@dataclass(frozen=True)
class TemplateFileSkip:
    """A template that could not be read; no file contents in diagnostics."""

    filename: str  # relative to PolicyDefinitions, including the ADML locale
    reason_class: str


def _read_template(path: Path) -> Element:
    """Decode XML bytes before parsing, retaining defusedxml protections.

    BOMs take precedence over declarations. Without a BOM, the opening XML
    byte pattern identifies UTF-16/32. Other files use their declared codec,
    falling back to UTF-8 only for unknown codec names (including "unicode").
    Decoding stays strict so corrupt bytes are reported instead of replaced.
    """
    data = path.read_bytes()
    if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        encoding = "utf-32"
    elif data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding = "utf-16"
    elif data.startswith(codecs.BOM_UTF8):
        encoding = "utf-8-sig"
    elif data.startswith(b"<\x00\x00\x00"):
        encoding = "utf-32-le"
    elif data.startswith(b"\x00\x00\x00<"):
        encoding = "utf-32-be"
    elif data.startswith(b"<\x00"):
        encoding = "utf-16-le"
    elif data.startswith(b"\x00<"):
        encoding = "utf-16-be"
    else:
        encoding = "utf-8"
        # Only the ASCII XML declaration is inspected before decoding.
        declaration = _XML_DECLARATION.match(
            data[: data.find(b"?>") + 2].decode("ascii", errors="ignore")
        )
        declared = _XML_ENCODING.search(declaration.group()) if declaration else None
        if declared:
            try:
                codecs.lookup(declared[2])
            except LookupError:
                pass
            else:
                encoding = declared[2]

    xml = data.decode(encoding)
    # The bytes have already been decoded; a declaration must not re-encode
    # the Unicode input or send an unsupported name to the XML parser.
    xml = _XML_DECLARATION.sub(lambda m: _XML_ENCODING.sub("", m.group()), xml, count=1)
    return ET.fromstring(xml)


@dataclass(frozen=True)
class AdmxPolicy:
    """One ADMX policy definition."""

    name: str
    class_scope: str  # "Machine", "User", "Both"
    key: str  # registry key path
    value_name: str  # registry value name (may be empty)
    display_name_ref: str  # raw $(string.xxx) reference
    display_name: str  # resolved display name from ADML
    explain_text: str  # resolved explain text from ADML


@dataclass
class PolicyDefinitions:
    """Parsed contents of a PolicyDefinitions directory."""

    policies: list[AdmxPolicy] = field(default_factory=list)
    _by_registry_key: dict[str, list[AdmxPolicy]] = field(
        default_factory=dict,
        repr=False,
    )
    skipped_files: list[TemplateFileSkip] = field(default_factory=list)

    def lookup(self, key: str, value_name: str, *, side: Side | None = None) -> list[AdmxPolicy]:
        """Find policies matching a registry key and value name.

        ``key`` is the full hive-relative path (e.g.
        ``Software\\Microsoft\\...``).  ``value_name`` is the value
        (e.g. ``NoControlPanel``).  Matching is case-insensitive.
        """
        norm_key = key.lower().strip("\\")
        norm_val = value_name.lower()
        results: list[AdmxPolicy] = []
        for p in self.policies:
            if side is not None and p.class_scope not in (
                "Both",
                "Machine" if side == "Computer" else "User",
            ):
                continue
            if p.key.lower().strip("\\") == norm_key:
                if not p.value_name or p.value_name.lower() == norm_val:
                    results.append(p)
        return results

    def resolve_display_name(self, identity: str, *, side: Side | None = None) -> str | None:
        """Given a setting identity like ``key:valueName``, return the
        ADMX policy display name or None."""
        parts = identity.split(":", 1)
        key = parts[0] if parts else identity
        val = parts[1] if len(parts) > 1 else ""
        matches = self.lookup(key, val, side=side)
        if matches:
            return matches[0].display_name
        return None


def _ref_to_key(ref: str) -> str:
    """Extract the string id from a ``$(string.xxx)`` reference.

    ADMX uses ``$(string.LockoutPolicy)`` which maps to the ADML
    ``<string id="LockoutPolicy">`` element.  Strip the ``string.``
    prefix if present.
    """
    if ref.startswith("$(") and ref.endswith(")"):
        inner = ref[2:-1]
        if inner.startswith("string."):
            return inner[7:]
        return inner
    return ref


def _parse_adml_strings(adml_path: Path) -> dict[str, str]:
    """Parse an ADML file and return {string_id: text}."""
    root = _read_template(adml_path)
    strings: dict[str, str] = {}
    ns = _ADMX_NS
    for st in root.iter(f"{{{ns}}}stringTable"):
        for s in st.iter(f"{{{ns}}}string"):
            sid = s.get("id", "")
            if sid and s.text:
                strings[sid] = s.text.strip()
    return strings


def find_admx_dir(export_dir: str | Path) -> Path | None:
    """Auto-detect a PolicyDefinitions (Central Store) directory in an export.

    The collector copies ``\\\\domain\\SYSVOL\\domain\\Policies`` to
    ``SYSVOL-Policies/`` in the export. The Central Store — if present — lives
    at     ``SYSVOL-Policies/PolicyDefinitions/``. This function searches the
    export directory for that path and returns it, or ``None`` if not
    found. Matching is case-sensitive (matches the collector's output casing).

    Also checks ``PolicyDefinitions/`` directly under the export root (for
    standalone ADMX directories that aren't inside a SYSVOL copy).
    """
    base = Path(export_dir)
    candidates = [
        base / "SYSVOL-Policies" / "PolicyDefinitions",
        base / "PolicyDefinitions",
    ]
    for c in candidates:
        try:
            if c.is_dir():
                return c
        except OSError:
            continue
    return None


def admx_directories(value: str | Path | Sequence[str | Path]) -> list[Path]:
    """Path lists use the host's os.pathsep; CLI lists retain literal paths."""
    values = (
        value.split(os.pathsep)
        if isinstance(value, str)
        else [value]
        if isinstance(value, Path)
        else value
    )
    return list(dict.fromkeys(Path(v) for v in values if str(v).strip()))


def parse_admx_dirs(value: str | Path | Sequence[str | Path]) -> PolicyDefinitions:
    """Merge catalogues in supplied order; the first matching policy wins.

    Each directory resolves its own language resources. Identical policies are
    deduplicated and skipped-file diagnostics identify their source directory.
    No Microsoft's templates are bundled.
    """
    result = PolicyDefinitions()
    seen: set[AdmxPolicy] = set()
    directories = admx_directories(value)
    for index, directory in enumerate(directories, 1):
        parsed = parse_admx_dir(directory)
        for policy in parsed.policies:
            if policy not in seen:
                seen.add(policy)
                result.policies.append(policy)
        result.skipped_files.extend(
            TemplateFileSkip(
                f"directory-{index}/{s.filename}" if len(directories) > 1 else s.filename,
                s.reason_class,
            )
            for s in parsed.skipped_files
        )
    return result


def parse_admx_dir(policy_defs_dir: str | Path) -> PolicyDefinitions:
    """Parse all ``.admx`` and ``.adml`` files in a PolicyDefinitions directory.

    Resolves ``$(string.xxx)`` references using the ``en-US`` ADML files
    (falls back to the first available locale if en-US is missing).
    """
    base = Path(policy_defs_dir)
    try:
        if not base.is_dir():
            return PolicyDefinitions()
    except OSError:
        return PolicyDefinitions()

    # 1. Parse ADML strings — prefer en-US, fall back to first locale
    adml_strings: dict[str, str] = {}
    skipped_files: list[TemplateFileSkip] = []
    en_us = base / "en-US"
    try:
        adml_dir = en_us if en_us.is_dir() else None
    except OSError:
        adml_dir = None
    if adml_dir is None:
        # Find first locale directory
        try:
            children = sorted(base.iterdir())
        except OSError:
            children = []
        for child in children:
            try:
                if child.is_dir() and any(child.glob("*.adml")):
                    adml_dir = child
                    break
            except OSError:
                continue
    if adml_dir is not None:
        try:
            adml_files = sorted(adml_dir.glob("*.adml"))
        except OSError:
            adml_files = []
        for adml_file in adml_files:
            try:
                adml_strings.update(_parse_adml_strings(adml_file))
            except Exception as exc:
                # A template is optional enrichment; isolate every file failure,
                # including codec errors and defusedxml rejections.
                skipped_files.append(
                    TemplateFileSkip(str(adml_file.relative_to(base)), type(exc).__name__)
                )
                continue

    # 2. Parse ADMX files
    policies: list[AdmxPolicy] = []
    try:
        admx_files = sorted(base.glob("*.admx"))
    except OSError:
        admx_files = []
    for admx_file in admx_files:
        try:
            policies.extend(_parse_admx_policies(admx_file, adml_strings))
        except Exception as exc:
            skipped_files.append(
                TemplateFileSkip(str(admx_file.relative_to(base)), type(exc).__name__)
            )
            continue

    return PolicyDefinitions(policies=policies, skipped_files=skipped_files)


def _parse_admx_policies(admx_file: Path, adml_strings: dict[str, str]) -> list[AdmxPolicy]:
    """Build one file's policies atomically so failures cannot leak partial rows."""
    root = _read_template(admx_file)
    policies: list[AdmxPolicy] = []
    ns = _ADMX_NS
    for pol in root.iter(f"{{{ns}}}policy"):
        name = pol.get("name", "")
        class_scope = pol.get("class", "Both")
        key = pol.get("key", "")
        value_name = pol.get("valueName", "")
        display_ref = pol.get("displayName", "")
        explain_ref = pol.get("explainText", "")

        display_name = adml_strings.get(_ref_to_key(display_ref), display_ref)
        explain_text = adml_strings.get(_ref_to_key(explain_ref), "")

        policies.append(
            AdmxPolicy(
                name=name,
                class_scope=class_scope,
                key=key,
                value_name=value_name,
                display_name_ref=display_ref,
                display_name=display_name,
                explain_text=explain_text,
            )
        )

    return policies
