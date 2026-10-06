"""Calibrate copied estates without exposing their contents.

Run with the project's web/dev extras installed. This script is deliberately
outside the installed package. The sanitized report scans non-vocabulary string
values and stdout summarizes only counts. Opt-in detail examples contain estate
data and are written separately, outside Git worktrees.

Warning formats are discovered mechanically from the calls found by:
    rg 'warnings.warn|\\.(warning|error)\\(' src/gpo_lens
AST extraction preserves literal text and replaces interpolations; runtime
messages must match the complete source format before its template is counted.
"""

from __future__ import annotations

import argparse
import ast
import builtins
import contextlib
import csv
import dataclasses
import html
import io
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import tracemalloc
import warnings
import zipfile
from collections import Counter
from collections.abc import Callable, Iterator
from contextvars import ContextVar
from datetime import UTC, datetime
from functools import cache, partial
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import quote, unquote, urlencode

from defusedxml import ElementTree as ET
from starlette.exceptions import StarletteDeprecationWarning

import gpo_lens.ingest as ingest
from gpo_lens import queries, store
from gpo_lens.admx_parser import find_admx_dir, parse_admx_dir
from gpo_lens.briefing import build_briefing
from gpo_lens.danger import load_danger_rules
from gpo_lens.finding_model import compute_fingerprint
from gpo_lens.findings import candidates_from_estate, evaluate_finding_lifecycle_v2
from gpo_lens.model import SEVERITY_ORDER, Estate
from gpo_lens.safe_output import secret_values

SOURCE = Path(__file__).resolve().parents[1] / "src" / "gpo_lens"
# Conservative Microsoft allow-list, never populated from an export. Registry,
# security, scripts, folder redirection, software installation, public key.
# https://techcommunity.microsoft.com/blog/askperf/the-basics-of-group-policies/372404
CSE_GUIDS = frozenset(
    {
        "35378eac-683f-11d2-a89a-00c04fbbcfa2",
        "827d319e-6eac-11d2-a4ea-00c04f79f83a",
        "42b5faae-6536-11d2-ae5a-0000f87571e3",
        "25537ba6-77a8-11d2-9b6c-0000f8080861",
        "c6dc5466-785a-11d2-84d0-00c04fb169f7",
        "b1be8d72-6eac-11d2-a4ea-00c04f79f83a",
    }
)
# Report CSE labels through their fixed GUID identifiers, never the XML Name.
CSE_NAMES = {
    "registry": "35378eac-683f-11d2-a89a-00c04fbbcfa2",
    "security": "827d319e-6eac-11d2-a4ea-00c04f79f83a",
    "scripts": "42b5faae-6536-11d2-ae5a-0000f87571e3",
    "folder redirection": "25537ba6-77a8-11d2-9b6c-0000f8080861",
    "software installation": "c6dc5466-785a-11d2-84d0-00c04fb169f7",
    "public key": "b1be8d72-6eac-11d2-a4ea-00c04f79f83a",
}
STATES = ("normal", "blocked", "registry_pol")
EXPORT_FORMATS = ("md", "csv", "json")
ADMX_COMMAND = "admx-coverage"
GAP_KINDS = (
    "inaccessible",
    "collection_error",
    "missing_sysvol",
    "unreadable_sysvol",
    "corrupt_gpp_xml",
)
GUID = re.compile(r"(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b")
SECRET_NAME = re.compile(
    r"(?i)^(?:cpassword|password|passwd|pwd|secret|credential|token|"
    r"(?:access|auth|refresh)[_-]?token|private[_-]?key|api[_-]?key)$"
)
REGISTRY_NAMES = frozenset(
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
URI = re.compile(r"(?i)(?:[a-z][a-z0-9+.-]*://|\\\\|//)[^\s/@\\:]*:([^\s/@\\]+)@")
ASSIGNMENT = re.compile(
    r"""(?i)\b(cpassword|password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*(?:"([^"]*)"|'([^']*)'|([^\s;,<>]+))"""
)


def strings(value: object) -> Iterator[str]:
    """Traverse values, including nested JSON stored in SQLite text columns."""
    if isinstance(value, str):
        yield value
        if value.startswith(("{", "[")):
            try:
                yield from strings(json.loads(value))
            except (ValueError, RecursionError):
                pass
    elif dataclasses.is_dataclass(value) and not isinstance(value, type):
        for field in dataclasses.fields(value):
            if not field.name.startswith("_"):
                yield from strings(getattr(value, field.name))
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from strings(item)


def normalize_message(message: str) -> str:
    for pattern, replacement in (
        (r""""[^"\n]*"|'[^'\n]*'|`[^`\n]*`""", "<quoted>"),
        (GUID.pattern, "<guid>"),
        (r"(?i)\bS-\d+(?:-\d+)+\b", "<sid>"),
        (r"(?:[a-zA-Z]:[\\/]|\\\\|/)[^\s,;]*", "<path>"),
        (r"\b[\w-]+(?:\.[\w-]+)+\b", "<domain>"),
        (r"[^\x00-\x7f]+", "<text>"),
        (r"\b\d+(?:\.\d+)?\b", "<number>"),
    ):
        message = re.sub(pattern, replacement, message)
    return " ".join(message.split())


@cache
def source_messages() -> list[tuple[re.Pattern[str], str, str]]:
    """Allow only complete, statically extracted gpo-lens message formats."""
    formats: list[tuple[re.Pattern[str], str, str]] = []
    for path in sorted(SOURCE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
                continue
            if call.func.attr not in {"warn", "warning", "error"} or not call.args:
                continue
            node = call.args[0]
            parts: list[str | None] = []
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                parts = re.split(r"(%[sdr])", node.value)
                parts = [None if p in {"%s", "%d", "%r"} else p for p in parts]
            elif isinstance(node, ast.JoinedStr):
                parts = [
                    n.value if isinstance(n, ast.Constant) and isinstance(n.value, str) else None
                    for n in node.values
                ]
            if not parts or not any(p for p in parts):
                continue
            pattern = re.compile(
                "".join(re.escape(p) if p is not None else ".*?" for p in parts), re.S
            )
            raw = "".join(p if p is not None else "<value>" for p in parts)
            formats.append((pattern, normalize_message(raw), raw))
    return formats


@cache
def source_formats() -> list[tuple[re.Pattern[str], str]]:
    return [(pattern, template) for pattern, template, _ in source_messages()]


@dataclasses.dataclass
class Detail:
    """Estate-bearing examples, kept entirely outside the sanitized projection."""

    categories: dict[str, list[dict[str, Any]]] = dataclasses.field(
        default_factory=lambda: {
            name: []
            for name in (
                "warnings",
                "interpreter_warnings",
                "extensions",
                "blocked_or_unparsed_settings",
                "admx_gaps",
                "web_5xx",
                "slowest_routes",
                "redaction_leaks",
                "skipped_content",
            )
        }
    )
    extension_guids: dict[str, set[str]] = dataclasses.field(default_factory=dict)

    def add(self, category: str, example: dict[str, Any], *, priority: bool = False) -> None:
        rows = self.categories.setdefault(category, [])
        if example in rows:
            return
        if priority:
            rows.insert(0, example)
            del rows[10:]
        elif len(rows) < 10:
            rows.append(example)

    def warning(self, message: str) -> None:
        for pattern, _, raw in source_messages():
            if pattern.fullmatch(message):
                rows = self.categories.setdefault("warnings", [])
                row = next((r for r in rows if r["template"] == raw), None)
                if row is None and len(rows) < 10:
                    row = {"template": raw, "examples": []}
                    rows.append(row)
                if row is not None and message not in row["examples"] and len(row["examples"]) < 3:
                    row["examples"].append(message)
                break
        else:
            self.add("warnings", {"template": None, "examples": [message]})
        if re.search(r"skip|unparse|unread|corrupt|invalid", message, re.I):
            self.add("skipped_content", {"reason": message})

    def report(self) -> dict[str, Any]:
        return {
            "label": "CONTAINS ESTATE DATA — private calibration detail; never commit",
            "schema_version": 1,
            "example_limit_per_category": 10,
            "warning_example_limit": 3,
            "categories": self.categories,
        }


DETAIL: ContextVar[Detail | None] = ContextVar("calibration_detail", default=None)


class Capture(logging.Handler):
    def __init__(self, formats: list[tuple[re.Pattern[str], str]]) -> None:
        super().__init__(logging.WARNING)
        self.formats = formats
        self.counts: Counter[str] = Counter()
        self.other = 0
        self.interpreter: Counter[str] = Counter()
        self.exceptions: list[dict[str, object]] = []
        self.detail_exceptions: list[dict[str, Any]] = []

    def message(self, message: str) -> None:
        if detail := DETAIL.get():
            detail.warning(message)
        # Normalization alone cannot make an arbitrary message safe. The entire
        # original must match a source format; emit ONLY the source template.
        normalized = normalize_message(message)
        for pattern, template in self.formats:
            if pattern.fullmatch(message) and normalized:
                self.counts[template] += 1
                return
        self.other += 1

    def emit(self, record: logging.LogRecord) -> None:
        self.message(record.getMessage())
        if record.exc_info and record.exc_info[1]:
            self.exceptions.append(exception_info(record.exc_info[1]))
            if DETAIL.get() is not None:
                self.detail_exceptions.append(detail_exception(record.exc_info[1]))

    def warning(self, message: Warning, category: type[Warning], *args: Any, **kwargs: Any) -> None:
        # Starlette deliberately derives its deprecations from UserWarning.
        if issubclass(category, StarletteDeprecationWarning):
            category = DeprecationWarning
        # Fold into fixed interpreter categories. Neither arbitrary class names
        # nor messages enter the sanitized report or product warning categories.
        for kind in (ResourceWarning, DeprecationWarning, PendingDeprecationWarning, ImportWarning):
            if issubclass(category, kind):
                self.interpreter[kind.__name__] += 1
                if detail := DETAIL.get():
                    detail.add(
                        "interpreter_warnings", {"category": kind.__name__, "message": str(message)}
                    )
                return
        self.message(str(message))

    def report(self) -> dict[str, object]:
        return {
            "templates": dict(sorted(self.counts.items())),
            "other_warnings": self.other,
            "interpreter_warnings": dict(sorted(self.interpreter.items())),
        }


@contextlib.contextmanager
def private_output(capture: Capture) -> Iterator[None]:
    root = logging.getLogger()
    loggers = [root] + [
        logger
        for logger in logging.Logger.manager.loggerDict.values()
        if isinstance(logger, logging.Logger)
    ]
    saved = [(logger, logger.handlers[:], logger.propagate, logger.level) for logger in loggers]
    for logger in loggers:
        logger.handlers = []
        logger.propagate = True
    root.handlers = [capture]
    root.setLevel(logging.WARNING)
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with warnings.catch_warnings():
                warnings.simplefilter("always")
                with patch(
                    "warnings.showwarning",
                    side_effect=capture.warning,
                ):
                    yield
    finally:
        for logger, handlers, propagate, level in saved:
            logger.handlers = handlers
            logger.propagate = propagate
            logger.setLevel(level)


@cache
def exception_names() -> set[str]:
    allowed = {
        name
        for name, cls in vars(builtins).items()
        if isinstance(cls, type) and issubclass(cls, BaseException)
    } | {"ParseError", "BadZipFile", "DefusedXmlException", "EntitiesForbidden"}
    for path in SOURCE.rglob("*.py"):
        allowed.update(
            n.name for n in ast.walk(ast.parse(path.read_text())) if isinstance(n, ast.ClassDef)
        )
    return allowed


def exception_info(exc: BaseException) -> dict[str, object]:
    if isinstance(exc, BaseExceptionGroup):
        return exception_info(exc.exceptions[0])
    allowed = exception_names()
    name = type(exc).__name__
    locations = []
    tb = exc.__traceback__
    while tb:
        path = Path(tb.tb_frame.f_code.co_filename).resolve()
        if path.is_relative_to(SOURCE):
            locations.append(f"gpo_lens/{path.relative_to(SOURCE).as_posix()}:{tb.tb_lineno}")
        elif path == Path(__file__).resolve():
            locations.append(f"scripts/calibrate.py:{tb.tb_lineno}")
        tb = tb.tb_next
    return {"class": name if name in allowed else "Exception", "source": locations[-1:]}


def detail_exception(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, BaseExceptionGroup):
        return detail_exception(exc.exceptions[0])
    frames = []
    tb = exc.__traceback__
    while tb:
        path = Path(tb.tb_frame.f_code.co_filename).resolve()
        if path.is_relative_to(SOURCE):
            frames.append(
                {
                    "file": f"gpo_lens/{path.relative_to(SOURCE).as_posix()}",
                    "line": tb.tb_lineno,
                    "function": tb.tb_frame.f_code.co_name,
                }
            )
        tb = tb.tb_next
    return {"message": str(exc), "traceback": frames}


def measured(
    fn: Callable[[], Any],
    formats: list[tuple[re.Pattern[str], str]],
    *,
    private_exceptions: list[dict[str, Any]] | None = None,
) -> tuple[Any, dict[str, Any]]:
    capture = Capture(formats)
    started = time.perf_counter()
    result = None
    record: dict[str, Any] = {"exit_status": 0, "exceptions": []}
    with private_output(capture):
        try:
            result = fn()
        except SystemExit as exc:
            result = exc.code if isinstance(exc.code, int) else 1
            record["exit_status"] = result
            record["exceptions"].append(exception_info(exc))
        except Exception as exc:
            record["exit_status"] = 1
            record["exceptions"].append(exception_info(exc))
            if detail := DETAIL.get():
                if private_exceptions is not None:
                    private_exceptions.append(detail_exception(exc))
                detail.add(
                    "skipped_content",
                    {
                        "reason": "Operation could not complete",
                        "exception": detail_exception(exc),
                    },
                    priority=True,
                )
    record.update(wall_seconds=round(time.perf_counter() - started, 6), warnings=capture.report())
    record["exceptions"].extend(capture.exceptions)
    if private_exceptions is not None:
        private_exceptions.extend(capture.detail_exceptions)
    return result, record


def database_strings(conn: sqlite3.Connection) -> set[str]:
    values: set[str] = set()
    for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        quoted = '"' + table.replace('"', '""') + '"'
        for row in conn.execute(f"PRAGMA table_info({quoted})"):
            if "TEXT" not in row[2].upper():
                continue
            column = '"' + row[1].replace('"', '""') + '"'
            for (value,) in conn.execute(f"SELECT DISTINCT {column} FROM {quoted}"):
                values.update(strings(value))
    return values


class SanitizationError(Exception):
    def __init__(self, field: str) -> None:
        self.field = field
        super().__init__(field)


def self_check(report: object, denylist: set[str]) -> str:
    """Scan non-vocabulary string values; keys and numeric scalars are fixed.

    Paths use numeric dictionary positions so an injected key cannot leak via
    the rejection diagnostic. Exemptions are exact, source-derived literals,
    never substring exemptions. Scan both encoded and decoded string leaves.
    """
    needles = {s.casefold() for s in denylist if len(s) >= 4}
    allowed = own_vocabulary()

    def check(value: object, path: str) -> None:
        if isinstance(value, dict):
            for index, child in enumerate(value.values()):
                check(child, f"{path}[{index}]")
        elif isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                check(child, f"{path}[{index}]")
        elif isinstance(value, str) and value not in allowed:
            encoded = json.dumps(value, ensure_ascii=True)
            texts = [encoded.casefold()]
            if isinstance(value, str):
                texts.append(value.casefold())
            if any(needle in text for needle in needles for text in texts):
                raise SanitizationError(path)

    check(report, "$")
    serialized = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    return serialized


@dataclasses.dataclass
class InputFacts:
    denylist: set[str] = dataclasses.field(default_factory=set)
    extensions: Counter[str] = dataclasses.field(default_factory=Counter)
    secret_classes: dict[str, set[str]] = dataclasses.field(default_factory=dict)
    collection_errors: int = 0

    def secret(self, category: str, value: str) -> None:
        if value:
            self.secret_classes.setdefault(category, set()).add(value)
            self.denylist.add(value)

    def scan(self, value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(child, str):
                    lowered = str(key).lower()
                    if lowered in {
                        "gpcmachineextensionnames",
                        "gpcuserextensionnames",
                        "computerextensionnames",
                        "userextensionnames",
                        "extensionguid",
                        "cseguid",
                    }:
                        self.extensions.update(g.lower() for g in GUID.findall(child))
                    if lowered == "cpassword":
                        self.secret("cpassword", child)
                    elif lowered in REGISTRY_NAMES:
                        self.secret("registry_credential", child)
                    elif SECRET_NAME.fullmatch(lowered):
                        self.secret("credential_field", child)
                self.scan(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                self.scan(child)
        elif isinstance(value, str):
            self.denylist.add(value)
            for match in URI.finditer(value):
                self.secret("uri_userinfo", unquote(match[1]))
            for match in ASSIGNMENT.finditer(value):
                self.secret(
                    "credential_assignment", next(v for v in match.groups()[1:] if v is not None)
                )


def read_input(archive: Path, dest: Path, facts: InputFacts) -> Path:
    """Extract only the supplied archive, rejecting traversal and symlinks."""
    facts.denylist.update({str(archive), archive.name})
    with zipfile.ZipFile(archive) as zipped:
        total = 0
        for info in zipped.infolist():
            name = info.filename.replace("\\", "/")
            facts.denylist.update({info.filename, *Path(name).parts})
            target = (dest / name).resolve()
            if not target.is_relative_to(dest.resolve()) or name.startswith("/"):
                raise ValueError("invalid archive member")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("archive symlink")
            total += info.file_size
            if total > 2 * 1024**3 or info.file_size > 512 * 1024**2:
                raise ValueError("archive too large")
            if name.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zipped.open(info) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
            facts.denylist.add(str(target))
            if target.suffix.lower() == ".json":
                try:
                    data = json.loads(target.read_text(encoding="utf-8-sig"))
                    facts.scan(data)
                    if target.name.lower() == "collection-errors.json":
                        facts.collection_errors += len(data) if isinstance(data, list) else 1
                except (ValueError, UnicodeError) as exc:
                    if detail := DETAIL.get():
                        detail.add("skipped_content", {"file": name, "reason": str(exc)})
            elif target.suffix.lower() == ".xml":
                try:
                    tree = ET.parse(target)
                    if detail := DETAIL.get():
                        detail_xml(tree.getroot(), name, detail)
                    for elem in tree.iter():
                        facts.scan(elem.attrib)
                        if elem.text and elem.text.strip():
                            facts.scan(elem.text.strip())
                        tag = elem.tag.rsplit("}", 1)[-1]
                        if elem.text and SECRET_NAME.fullmatch(tag):
                            facts.secret(
                                "cpassword" if tag.lower() == "cpassword" else "credential_field",
                                elem.text.strip(),
                            )
                        attr_name = elem.get("name", elem.get("ValueName", "")).lower()
                        if attr_name in REGISTRY_NAMES or SECRET_NAME.fullmatch(attr_name):
                            for key in ("value", "data", "Value"):
                                if elem.get(key):
                                    facts.secret("registry_credential", elem.get(key, ""))
                        if tag == "Extension":
                            for value in elem.attrib.values():
                                facts.extensions.update(g.lower() for g in GUID.findall(value))
                except (ET.ParseError, ValueError, UnicodeError) as exc:
                    if detail := DETAIL.get():
                        detail.add("skipped_content", {"file": name, "reason": str(exc)})
    reports = list(dest.rglob("AllGPOs.xml"))
    if len(reports) != 1:
        raise ValueError("primary report count")
    return reports[0].parent


def element_examples(element: Any) -> dict[str, list[str]]:
    paths = []
    names = []
    for child in element.iter():
        if child.tag.rsplit("}", 1)[-1] == "Name" and child.text and child.text.strip():
            names.append(child.text.strip())
        if child.get("name"):
            names.append(child.get("name"))
        if child.tag.rsplit("}", 1)[-1].lower() in {"key", "keyname", "keypath"}:
            if child.text and child.text.strip():
                paths.append(child.text.strip())
        paths.extend(
            v for k, v in child.attrib.items() if k.lower() in {"key", "keyname", "keypath"}
        )
    return {
        "element_names": list(dict.fromkeys(c.tag.rsplit("}", 1)[-1] for c in element.iter()))[:10],
        "registry_paths": list(dict.fromkeys(paths))[:10],
        "setting_names": list(dict.fromkeys(names))[:10],
    }


def detail_xml(root: Any, filename: str, detail: Detail) -> None:
    for gpo in root.iter():
        if gpo.tag.rsplit("}", 1)[-1] != "GPO":
            continue
        name = ingest._text(ingest._child_by_localname(gpo, "Name")) or ""
        for side in ("Computer", "User"):
            side_elem = ingest._child_by_localname(gpo, side)
            if side_elem is None:
                continue
            for ext_data in ingest._children_by_localname(side_elem, "ExtensionData"):
                cse = ingest._text(ingest._child_by_localname(ext_data, "Name")) or "Unknown"
                extensions = ingest._children_by_localname(ext_data, "Extension")
                if not extensions:
                    detail.add(
                        "skipped_content",
                        {
                            "file": filename,
                            "gpo": name,
                            "extension": cse,
                            "side": side,
                            "reason": "ExtensionData has no Extension element",
                            **element_examples(ext_data),
                        },
                    )
                for ext in extensions:
                    guids = sorted(
                        {g.lower() for v in ext.attrib.values() for g in GUID.findall(v)}
                    )
                    detail.extension_guids.setdefault(cse, set()).update(guids)
                    if any(g not in CSE_GUIDS for g in guids):
                        detail.add(
                            "extensions",
                            {
                                "file": filename,
                                "gpo": name,
                                "extension": cse,
                                "guids": guids,
                                "side": side,
                                "reason": "GUID outside the harness Microsoft CSE allow-list",
                                **element_examples(ext),
                            },
                        )
                    if not list(ext):
                        detail.add(
                            "skipped_content",
                            {
                                "file": filename,
                                "gpo": name,
                                "extension": cse,
                                "guids": guids,
                                "side": side,
                                "reason": "Extension has no setting blocks",
                            },
                        )


@contextlib.contextmanager
def detail_ingest() -> Iterator[None]:
    """Observe the parser's actual fallback/skip branches without changing it."""
    detail = DETAIL.get()
    if detail is None:
        yield
        return
    generic = ingest._parse_generic_setting
    single = ingest._parse_single_gpo
    settings_parser = ingest._parse_settings
    registry_parser = ingest._parse_gpp_registry
    container_parser = ingest._parse_gpp_container
    block_context: dict[int, dict[str, str]] = {}

    def settings(element: Any, gpo_id: str) -> Any:
        for side in ("Computer", "User"):
            side_elem = ingest._child_by_localname(element, side)
            if side_elem is None:
                continue
            for ext_data in ingest._children_by_localname(side_elem, "ExtensionData"):
                cse = ingest._text(ingest._child_by_localname(ext_data, "Name")) or "Unknown"
                for extension in ingest._children_by_localname(ext_data, "Extension"):
                    for block in extension:
                        block_context[id(block)] = {
                            "extension": cse,
                            "gpo_id": gpo_id,
                            "side": side,
                        }
        try:
            return settings_parser(element, gpo_id)
        finally:
            block_context.clear()

    def registry(block: Any) -> Any:
        parsed = registry_parser(block)
        if parsed:
            retained = [row[3] for row in parsed]
            for props in block.iter():
                if (
                    props.tag.rsplit("}", 1)[-1] == "Properties"
                    and ingest.element_to_dict(props) not in retained
                ):
                    detail.add(
                        "skipped_content",
                        {
                            **block_context.get(id(block), {"extension": "Registry"}),
                            "reason": "GPP Registry Properties not emitted (no key or hive)",
                            **element_examples(props),
                        },
                    )
        return parsed

    def container(block: Any) -> Any:
        parsed = container_parser(block)
        if parsed:
            retained = [row[3] for row in parsed]
            for child in block:
                if ingest.element_to_dict(child) not in retained:
                    detail.add(
                        "skipped_content",
                        {
                            **block_context.get(
                                id(block), {"extension": block.tag.rsplit("}", 1)[-1]}
                            ),
                            "reason": "GPP container child not emitted (missing uid)",
                            **element_examples(child),
                        },
                    )
        return parsed

    def fallback(cse: str, block: Any) -> Any:
        examples = element_examples(block)
        detail.add(
            "blocked_or_unparsed_settings",
            {
                "extension": cse,
                "reason": "Generic parser fallback; no CSE-specific classification",
                **examples,
            },
        )
        detail.add(
            "extensions",
            {
                "extension": cse,
                "guids": sorted(detail.extension_guids.get(cse, set())),
                "reason": "Generic parser fallback",
                **examples,
            },
        )
        detail.add(
            "skipped_content",
            {
                "extension": cse,
                "reason": "Preserved generically; no CSE-specific classification",
                **examples,
            },
        )
        return generic(cse, block)

    def gpo(element: Any) -> Any:
        result = single(element)
        if result is None:
            detail.add(
                "skipped_content",
                {
                    "gpo": ingest._text(ingest._child_by_localname(element, "Name")),
                    "reason": "GPO has no valid identifier",
                },
            )
        return result

    with (
        patch.object(ingest, "_parse_generic_setting", fallback),
        patch.object(ingest, "_parse_single_gpo", gpo),
        patch.object(ingest, "_parse_settings", settings),
        patch.object(ingest, "_parse_gpp_registry", registry),
        patch.object(ingest, "_parse_gpp_container", container),
    ):
        yield


def guid_counts(values: Counter[str]) -> dict[str, object]:
    return {
        "allowlisted": {g: values[g] for g in sorted(CSE_GUIDS) if values[g]},
        "unknown_guid_count": sum(n for g, n in values.items() if g not in CSE_GUIDS),
        "unknown_guid_distinct_count": len(set(values) - CSE_GUIDS),
    }


def enum_counts(values: Iterator[str], allowed: tuple[str, ...]) -> dict[str, int]:
    counts = Counter(values)
    return {
        **{key: counts[key] for key in allowed},
        "other_count": sum(n for k, n in counts.items() if k not in allowed),
    }


def estate_counts(
    estate: Estate, facts: InputFacts, conn: sqlite3.Connection, snapshot_id: int
) -> dict[str, object]:
    settings = [s for g in estate.gpos for s in g.settings]
    cse = Counter(CSE_NAMES[s.cse.lower()] for s in settings if s.cse.lower() in CSE_NAMES)
    # The measured snapshot is authoritative even when an in-memory estate
    # projection omits principals. Restrict the count to this export's snapshot.
    principals = dict(
        conn.execute(
            "SELECT resolved, COUNT(*) FROM principal WHERE snapshot_id=? GROUP BY resolved",
            (snapshot_id,),
        )
    )
    return {
        "gpos": len(estate.gpos),
        "soms": len(estate.soms),
        "links": sum(len(g.links) for g in estate.gpos),
        "som_links": sum(len(s.links) for s in estate.soms),
        "settings": len(settings),
        "settings_by_cse": {
            "allowlisted": dict(sorted(cse.items())),
            "other_count": sum(s.cse.lower() not in CSE_NAMES for s in settings),
            "other_group_counts": sorted(
                Counter(s.cse for s in settings if s.cse.lower() not in CSE_NAMES).values(),
                reverse=True,
            ),
        },
        "extensions": guid_counts(facts.extensions),
        "settings_by_source_state": enum_counts((s.source_state for s in settings), STATES),
        "wmi_filters": len(estate.wmi_filters),
        "principals_resolved": principals.get(1, 0),
        "principals_unresolved": principals.get(0, 0),
        "coverage_gaps_by_kind": enum_counts((g.kind for g in estate.coverage_gaps), GAP_KINDS),
        "collection_errors": facts.collection_errors,
    }


@cache
def own_codes() -> set[str]:
    codes = {r.id for r in load_danger_rules()}
    for path in (
        SOURCE / "danger.py",
        SOURCE / "queries" / "_doctor.py",
        *sorted((SOURCE / "detection").rglob("*.py")),
    ):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.keyword) and node.arg in {"category", "check_id", "ref_type"}:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    codes.add(node.value.value)
    codes |= {"danger:" + code for code in list(codes)}
    codes |= {"broken_ref:" + code for code in list(codes)}
    return codes


@cache
def own_vocabulary() -> frozenset[str]:
    """Exact vocabulary from trusted code/schema, independent of estate data.

    Do not collect every source string: paths, examples and setting values in
    source are not enums. Only Literal/Enum declarations and the harness's
    explicitly projected vocabularies cross this boundary.
    """
    from gpo_lens.cli import _core

    allowed = own_codes() | set(SEVERITY_ORDER) | exception_names()
    allowed.update(CSE_GUIDS)
    allowed.update(STATES)
    allowed.update(GAP_KINDS)
    allowed.update(EXPORT_FORMATS)
    allowed.add(ADMX_COMMAND)
    allowed.update(c.name for c in _core._COMMANDS)
    allowed.update(template for _, template, _ in source_messages())
    for path in sorted(SOURCE.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            enum_node: ast.AST | None = None
            if isinstance(node, ast.Subscript) and (
                isinstance(node.value, ast.Name)
                and node.value.id == "Literal"
                or isinstance(node.value, ast.Attribute)
                and node.value.attr == "Literal"
            ):
                enum_node = node.slice
            elif isinstance(node, ast.ClassDef) and any(
                isinstance(base, ast.Name) and base.id in {"Enum", "StrEnum", "IntEnum"}
                for base in node.bases
            ):
                for stmt in node.body:
                    if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                        allowed.update(
                            n.value
                            for n in ast.walk(stmt.value)
                            if isinstance(n, ast.Constant) and isinstance(n.value, str)
                        )
            if enum_node is not None:
                allowed.update(
                    n.value
                    for n in ast.walk(enum_node)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str)
                )
            # Route declarations, including the fixed static mount.
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in {"app", "router"}
            ):
                if node.func.attr in {"get", "post", "put", "patch", "delete", "mount"}:
                    if node.args and isinstance(node.args[0], ast.Constant):
                        value = node.args[0].value
                        if isinstance(value, str) and value.startswith("/"):
                            allowed.add(value)
                            if node.func.attr != "mount":
                                allowed.add(node.func.attr.upper())
        allowed.update(
            f"gpo_lens/{path.relative_to(SOURCE).as_posix()}:{line}"
            for line in range(1, len(source.splitlines()) + 1)
        )
    allowed.update(
        f"scripts/calibrate.py:{line}"
        for line in range(1, len(Path(__file__).read_text().splitlines()) + 1)
    )
    # Table names are initialized from the application's schema, never read
    # from the data-bearing calibration DB for the purposes of exemptions.
    with contextlib.closing(sqlite3.connect(":memory:")) as conn, conn:
        store.init_db(conn)
        allowed.update(
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        )
    return frozenset(allowed)


def run_command(
    db: Path, name: str, args: list[str], formats: list[tuple[re.Pattern[str], str]]
) -> tuple[Any, dict[str, Any]]:
    from gpo_lens.cli import _core

    output = io.StringIO()
    exceptions: list[dict[str, object]] = []
    command = next(c for c in _core._COMMANDS if c.name == name)
    original = command.func

    def wrapped(namespace: argparse.Namespace) -> Any:
        try:
            return original(namespace)
        except Exception as exc:
            exceptions.append(exception_info(exc))
            raise

    def invoke() -> int:
        with patch.object(command, "func", wrapped), contextlib.redirect_stdout(output):
            return _core.main(["--db", str(db), "--json", name, *args])

    status, record = measured(invoke, formats)
    record.update(name=name, exit_status=status if status is not None else 1)
    record["exceptions"].extend(exceptions)
    payload = None
    if status == 0:
        try:
            payload = json.loads(output.getvalue())["data"]
        except (ValueError, KeyError, TypeError):
            record["exit_status"] = 1
    return payload, record


def analysis(
    db: Path,
    estate: Estate,
    sid: int,
    formats: list[tuple[re.Pattern[str], str]],
    admx_dir: Path | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    results: dict[str, Any] = {}
    commands = []
    signatures: dict[str, Any] = {}
    allowed = own_codes()
    for name in ("doctor", "danger", "admx-gaps", "broken-refs", "topology-check"):
        payload, record = run_command(
            db,
            name,
            ["--admx-dir", str(admx_dir)] if admx_dir and name in {"danger", "admx-gaps"} else [],
            formats,
        )
        commands.append(record)
        signatures[name] = payload
        rows = payload.get("findings", []) if isinstance(payload, dict) else payload or []
        counts: dict[str, object] = {"count": len(rows)}
        if name in {"doctor", "danger"}:
            groups: Counter[tuple[str, str]] = Counter()
            other = 0
            for row in rows:
                code = row.get("category" if name == "doctor" else "check_id", "")
                severity = row.get("severity", "")
                if code in allowed and severity in SEVERITY_ORDER:
                    groups[code, severity] += 1
                else:
                    other += 1
            counts.update(
                by_code_severity=[
                    {"code": code, "severity": sev, "count": n}
                    for (code, sev), n in sorted(groups.items())
                ],
                other_count=other,
            )
        if name == "admx-gaps":
            if detail := DETAIL.get():
                for row in rows:
                    detail.add(
                        "admx_gaps",
                        {
                            "key_path": row["key_path"],
                            "value_name": row["value_name"],
                            "gpo": row["gpo_name"],
                            "side": row["side"],
                        },
                    )
            registry_keys = {
                (g.id, setting.side, setting.identity)
                for g in estate.gpos
                for setting in g.settings
                if setting.cse.lower() == "registry"
            }
            attributed = sum((r["gpo_id"], r["side"], r["identity"]) in registry_keys for r in rows)
            counts["extensions"] = {
                "allowlisted": {CSE_NAMES["registry"]: attributed},
                "unattributed_count": len(rows) - attributed,
            }
        results[name] = counts
    with contextlib.closing(sqlite3.connect(db)) as conn, conn:
        briefing, record = measured(lambda: build_briefing(conn, as_of_snapshot=sid), formats)
    record["name"] = "export"
    commands.append(record)
    results["briefing"] = (
        {
            f.name: getattr(briefing, f.name)
            for f in dataclasses.fields(briefing)
            if type(getattr(briefing, f.name)) is int
        }
        if briefing
        else {"count": 0}
    )
    results["briefing"].update(
        vitals_count=len(briefing.vitals) if briefing else 0,
        problems_count=len(briefing.problems) if briefing else 0,
    )
    return results, commands, signatures


def response_rows(body: str, format: str) -> int:
    if format == "json":
        data = json.loads(body)
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict):
            return len(data.get("settings", [])) if isinstance(data.get("settings"), list) else 1
        return 0
    if format == "csv":
        rows = list(csv.reader(io.StringIO(body)))
    else:
        rows = [
            [cell.strip() for cell in line.strip().strip("|").split("|")]
            for line in body.splitlines()
            if line.startswith("|") and "| ---" not in line
        ]
    if not rows:
        return 0
    if rows[0] == ["section", "record", "field", "value"]:
        return len({(r[0], r[1]) for r in rows[1:] if len(r) >= 2 and r[0] != "metadata"})
    return max(0, len(rows) - 1)


def leak_count(body: str, secrets: set[str]) -> int:
    # Decode common transport/render encodings in addition to the literal body.
    texts = {body, html.unescape(body), unquote(body)}
    try:
        texts.update(strings(json.loads(body)))
    except (ValueError, RecursionError):
        pass
    return sum(bool(s) and any(s in text for text in texts) for s in secrets)


def leak_fields(body: str, secrets: set[str], fmt: str) -> list[str]:
    """Locate leaks without returning the matched value, even in field names."""
    fields: list[str] = []

    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for index, (key, child) in enumerate(value.items()):
                label = f"[{index}]" if leak_count(str(key), secrets) else f".{key}"
                if leak_count(str(key), secrets):
                    fields.append(f"{path}[key:{index}]")
                walk(child, path + label)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]")
        elif isinstance(value, str) and leak_count(value, secrets):
            fields.append(path)

    try:
        walk(json.loads(body), "$")
    except (ValueError, RecursionError):
        if fmt in {"csv", "md"}:
            rows = (
                list(csv.reader(io.StringIO(body)))
                if fmt == "csv"
                else [
                    [cell.strip() for cell in line.strip().strip("|").split("|")]
                    for line in body.splitlines()
                    if line.startswith("|")
                ]
            )
            for row in rows[1:]:
                for index, value in enumerate(row):
                    if leak_count(value, secrets):
                        label = rows[0][index] if index < len(rows[0]) else str(index)
                        fields.append(f"column[{index}]" if leak_count(label, secrets) else label)
        if not fields and leak_count(body, secrets):
            fields.append("response.body")
    return list(dict.fromkeys(fields))[:10]


def web_probe(
    db: Path,
    estate: Estate,
    archive: Path,
    formats: list[tuple[re.Pattern[str], str]],
    secrets: set[str],
    admx_dir: Path,
    denylist: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    from fastapi.routing import APIRoute
    from fastapi.testclient import TestClient

    from gpo_lens.query_dispatch import QUERY_REQUIRED_PARAMS, VALID_QUERIES
    from gpo_lens.web.app import create_app
    from gpo_lens.web.auth import LOCAL_PRINCIPAL, get_principal

    app = create_app(str(db), admx_dir=str(admx_dir))
    app.dependency_overrides[get_principal] = lambda: LOCAL_PRINCIPAL
    for limiter in (
        app.state.rate_limit_ask,
        app.state.rate_limit_ingest,
        app.state.rate_limit_general,
    ):
        # The measurement client must reach the full route × format inventory.
        # Change its actual budget; production defaults remain intact.
        limiter._max_requests = 1000000
    with contextlib.closing(sqlite3.connect(db)) as conn, conn:
        finding = conn.execute("SELECT id FROM finding ORDER BY id LIMIT 1").fetchone()
        snapshot_id = conn.execute("SELECT MAX(id) FROM snapshot").fetchone()[0]
    ids = {
        "gpo_id": estate.gpos[0].id if estate.gpos else "0" * 32,
        "path": next((s.path for s in estate.soms if s.container_type != "site"), "calibration"),
        "finding_id": str(finding[0]) if finding else "0",
        "query_name": "estate_summary",
    }
    comparator = io.BytesIO()
    with zipfile.ZipFile(archive) as exported, zipfile.ZipFile(comparator, "w") as baseline:
        for member in exported.infolist():
            if member.filename.replace("\\", "/").rsplit("/", 1)[-1] == "AllGPOs.xml":
                baseline.writestr("GPOs/calibration/gpreport.xml", exported.read(member))
                break
    comparator_bytes = comparator.getvalue()
    records = []
    leaks: Counter[str] = Counter()
    with TestClient(app, raise_server_exceptions=True) as client:
        for route in app.routes:
            template = getattr(route, "path", "/static")
            if not isinstance(route, APIRoute):
                # Probe the static mount's own, fixed asset (no estate input).
                variants: list[tuple[str, str, str, dict[str, str]]] = [
                    ("GET", "", "/static/css/tokens.css", {})
                ]
            else:
                url = template
                for key, value in ids.items():
                    url = re.sub(r"\{" + key + r"(?::[^}]+)?\}", quote(value, safe=""), url)
                params = {}
                if template == "/setting":
                    params["identity"] = next(
                        (s.identity for g in estate.gpos for s in g.settings), "calibration"
                    )
                if template == "/search":
                    params["q"] = next(
                        (s.display_name for g in estate.gpos for s in g.settings), "calibration"
                    )
                if template == "/findings":
                    params.update(lifecycle="all", per_page="all")
                variants = []
                for method in sorted(route.methods):
                    variants.append((method, "", url, params))
                    if method == "POST" and (
                        template in {"/ingest", "/ingest/delete"} or template.endswith("/triage")
                    ):
                        variants.append((method, "", url, {**params, "_invalid": "1"}))
                    has_format = any(
                        p.name == "format"
                        for p in route.dependant.query_params + route.dependant.body_params
                    )
                    if has_format:
                        available = (
                            ("csv", "json")
                            if template.startswith("/export/ou/")
                            else EXPORT_FORMATS
                            if template.startswith("/export/")
                            else ("md", "csv")
                        )
                        variants.extend(
                            (method, fmt, url, {**params, "format": fmt}) for fmt in available
                        )
                if template == "/api/v1/query/{query_name}":
                    variants = [
                        (
                            "GET",
                            "",
                            template.replace("{query_name}", q),
                            {
                                k: ids.get(
                                    k,
                                    params.get(
                                        k,
                                        next(
                                            (
                                                setting.identity
                                                for g in estate.gpos
                                                for setting in g.settings
                                            ),
                                            "calibration",
                                        )
                                        if k == "identity"
                                        else ids["path"]
                                        if k == "som_path"
                                        else next(iter(estate.principals), "S-1-5-11")
                                        if k == "principal_sid"
                                        else "calibration",
                                    ),
                                )
                                for k in QUERY_REQUIRED_PARAMS.get(q, [])
                            },
                        )
                        for q in sorted(VALID_QUERIES)
                    ]
            for method, fmt, url, params in variants:

                def request(
                    method: str = method,
                    url: str = url,
                    params: dict[str, str] = params,
                    template: str = template,
                ) -> Any:
                    if method == "POST":
                        data: dict[str, Any] = dict(params)
                        files = None
                        if template in {"/baseline", "/golden-diff"}:
                            files = {
                                "file": ("calibration.zip", comparator_bytes, "application/zip")
                            }
                        elif template == "/ingest":
                            files = {
                                "file": (
                                    "calibration.zip",
                                    b"invalid" if params.get("_invalid") else archive.read_bytes(),
                                    "application/zip",
                                )
                            }
                        elif template == "/ask":
                            data["question"] = "calibration"
                        elif template.endswith("/triage"):
                            data["status"] = "invalid" if params.get("_invalid") else "acknowledged"
                        elif template == "/ingest/delete":
                            data["snapshot_id"] = -1 if params.get("_invalid") else snapshot_id
                        elif template == "/resultant" and estate.principals:
                            data["principal_sid"] = next(iter(estate.principals))
                            data["dn"] = ids["path"]
                        return client.request(
                            method,
                            url,
                            data=data,
                            files=files,
                            headers={"Origin": "http://testserver"},
                            follow_redirects=True,
                        )
                    return client.request(method, url, params=params, follow_redirects=True)

                # Exercise valid mutation routes on a disposable DB copy. The
                # measured estate history retains exactly the requested order.
                sandbox = db.parent / "web-probe.sqlite3"
                if method == "POST":
                    sandbox.unlink(missing_ok=True)
                    with (
                        contextlib.closing(sqlite3.connect(db)) as original_conn,
                        original_conn,
                        contextlib.closing(sqlite3.connect(sandbox)) as probe_conn,
                        probe_conn,
                    ):
                        original_conn.backup(probe_conn)
                    app.state.db_path = str(sandbox)
                try:
                    failure: list[dict[str, Any]] = []
                    response, record = measured(request, formats, private_exceptions=failure)
                    if method == "POST" and denylist is not None:
                        with contextlib.closing(sqlite3.connect(sandbox)) as probe_conn, probe_conn:
                            denylist.update(database_strings(probe_conn))
                finally:
                    app.state.db_path = str(db)
                record.update(
                    route_template=template,
                    method=method,
                    validation_case=int(bool(params.get("_invalid"))),
                    format=fmt,
                    status_code=response.status_code if response is not None else 500,
                    response_bytes=len(response.content) if response is not None else 0,
                )
                if fmt:
                    record["row_count"] = None
                if response is not None:
                    leaks[template] += leak_count(response.text, secrets)
                    if fmt and response.status_code == 200:
                        rows, row_record = measured(
                            partial(response_rows, response.text, fmt), formats
                        )
                        record["row_count"] = rows
                        record["exceptions"].extend(row_record["exceptions"])
                if detail := DETAIL.get():
                    concrete_url = url
                    if method != "POST" and params:
                        concrete_url += "?" + urlencode(params)
                    example = {
                        "route": template,
                        "method": method,
                        "url": concrete_url,
                        "wall_seconds": record["wall_seconds"],
                    }
                    slowest = detail.categories.setdefault("slowest_routes", [])
                    slowest.append(example)
                    slowest.sort(key=lambda r: -r["wall_seconds"])
                    del slowest[10:]
                    if record["status_code"] >= 500:
                        detail.add(
                            "web_5xx",
                            {
                                **example,
                                "status_code": record["status_code"],
                                "exceptions": failure,
                            },
                        )
                    if response is not None:
                        for field in leak_fields(response.text, secrets, fmt):
                            detail.add("redaction_leaks", {"route": template, "field": field})
                records.append(record)
    return records, dict(sorted(leaks.items()))


def calibrate(archives: list[Path], scratch: Path) -> tuple[dict[str, Any], set[str]]:
    formats = source_formats()
    db = scratch / "estate.sqlite3"
    conn = sqlite3.connect(db)
    try:
        store.init_db(conn)
        report: dict[str, Any] = {
            "schema_version": 1,
            "ingest": [],
            "analysis": [],
            "commands": [],
            "web": [],
            "redaction": {},
        }
        denylist: set[str] = set()
        secrets_by_class: dict[str, set[str]] = {}
        snapshots = []
        last_estate = None
        last_source = None
        last_archive = None
        empty_admx = scratch / "PolicyDefinitions"
        empty_admx.mkdir()
        last_admx_dir = empty_admx
        for index, archive in enumerate(archives):
            facts = InputFacts()
            dest = scratch / f"input-{index}"
            dest.mkdir()
            tracemalloc.start()
            tracemalloc.reset_peak()

            def load(
                archive: Path = archive, dest: Path = dest, facts: InputFacts = facts
            ) -> tuple[Estate, int, Path]:
                src = read_input(archive, dest, facts)
                with detail_ingest():
                    estate = ingest.load_estate(src)
                sid = store.save_estate(conn, estate)
                return estate, sid, src

            loaded, record = measured(load, formats)
            record.update(
                export_index=index,
                peak_memory_bytes=tracemalloc.get_traced_memory()[1],
                archive_bytes=archive.stat().st_size if archive.is_file() else 0,
            )
            tracemalloc.stop()
            denylist.update(facts.denylist)
            if loaded is not None:
                estate, sid, src = loaded
                denylist.update(strings(estate))
                # The product's detector supplies additional credential forms.
                facts.scan(dataclasses.asdict(estate))
                known = (
                    set().union(*facts.secret_classes.values()) if facts.secret_classes else set()
                )
                for value in secret_values(estate):
                    if value not in known:
                        facts.secret(
                            "registry_credential"
                            if any(
                                s.display_value == value
                                and s.cse.lower() in {"registry", "windows registry"}
                                for g in estate.gpos
                                for s in g.settings
                            )
                            else "credential_field",
                            value,
                        )
                for hit in queries.cpassword_scan(estate):
                    facts.secret("cpassword", hit.cpassword)
                for category, values in facts.secret_classes.items():
                    secrets_by_class.setdefault(category, set()).update(values)
                record.update(snapshot_id=sid, counts=estate_counts(estate, facts, conn, sid))
                if detail := DETAIL.get():
                    for gpo in estate.gpos:
                        for setting in gpo.settings:
                            if setting.source_state == "blocked":
                                detail.add(
                                    "blocked_or_unparsed_settings",
                                    {
                                        "extension": setting.cse,
                                        "source_state": setting.source_state,
                                        "gpo": gpo.name,
                                        "side": setting.side,
                                        "element_names": [setting.display_name],
                                        "registry_paths": [],
                                        "reason": "Blocked extension remains unresolved",
                                    },
                                )
                    for guid in sorted(set(facts.extensions) - CSE_GUIDS):
                        detail.add(
                            "extensions",
                            {
                                "guid": guid,
                                "reason": "Unallowlisted extension reference in collector input",
                            },
                        )
                admx_dir = find_admx_dir(src) or empty_admx
                admx, admx_record = measured(partial(parse_admx_dir, admx_dir), formats)
                admx_record["name"] = ADMX_COMMAND
                report["commands"].append(admx_record)
                lifecycle, evaluation = measured(
                    partial(evaluate_finding_lifecycle_v2, conn, sid, estate, admx=admx), formats
                )
                evaluation["name"] = "doctor"
                evaluation["snapshot_id"] = sid
                evaluation["duplicate_fingerprint_count"] = (
                    lifecycle.duplicate_fingerprint_count if lifecycle else None
                )
                evaluation["degraded_analysis"] = bool(
                    lifecycle and lifecycle.duplicate_fingerprint_count
                )
                report["commands"].append(evaluation)
                results, commands, _ = analysis(db, estate, sid, formats, admx_dir)
                report["analysis"].append({"snapshot_id": sid, **results})
                report["commands"].extend(commands)
                snapshots.append(sid)
                last_estate, last_source, last_archive = estate, src, archive
                last_admx_dir = admx_dir
            report["ingest"].append(record)
        report["diffs"] = []
        for a, b in zip(snapshots, snapshots[1:], strict=False):
            diff: dict[str, Any] = {"snapshot_a": a, "snapshot_b": b}
            for name in ("diff", "diff-settings", "changelog"):
                payload, record = run_command(db, name, [str(a), str(b)], formats)
                report["commands"].append(record)
                if name == "diff" and isinstance(payload, dict):
                    diff[name] = {
                        key: len(value) for key, value in payload.items() if isinstance(value, list)
                    }
                    diff[name]["gpos_changed"] = len(
                        set(payload["settings_changed"])
                        | set(payload["links_changed"])
                        | set(payload["delegation_changed"])
                        | {r["gpo_id"] for r in payload["metadata_changes"]}
                    )
                elif name == "diff-settings" and isinstance(payload, list):
                    diff[name] = enum_counts(
                        (r["change_type"] for r in payload), ("added", "removed", "modified")
                    )
                else:
                    diff[name] = {"count": len(payload) if isinstance(payload, list) else 0}
            report["diffs"].append(diff)
        secrets = set().union(*secrets_by_class.values()) if secrets_by_class else set()
        if last_estate is not None and last_archive is not None:
            probed, record = measured(
                partial(
                    web_probe,
                    db,
                    last_estate,
                    last_archive,
                    formats,
                    secrets,
                    last_admx_dir,
                    denylist,
                ),
                formats,
            )
            web, leaks = probed if probed is not None else ([], {})
            report["web"] = web
            report["web_probe"] = record
            report["redaction"] = {
                "detected_by_class": {k: len(v) for k, v in sorted(secrets_by_class.items())},
                "leaks_by_route_template": leaks,
            }
        report["determinism"] = {"identical": False, "exceptions": []}
        if last_source is not None:

            def repeat() -> dict[str, object]:
                # Fresh DBs isolate snapshot ids, lifecycle and clock history.
                observations = []
                for repeat_index in range(2):
                    estate = ingest.load_estate(last_source)
                    repeat_db = scratch / f"repeat-{repeat_index}.sqlite3"
                    with contextlib.closing(sqlite3.connect(repeat_db)) as repeat_conn, repeat_conn:
                        store.init_db(repeat_conn)
                        repeat_sid = store.save_estate(
                            repeat_conn, estate, taken_at=datetime(2026, 1, 1, tzinfo=UTC)
                        )
                        admx = parse_admx_dir(last_admx_dir)
                        lifecycle = evaluate_finding_lifecycle_v2(
                            repeat_conn, repeat_sid, estate, admx=admx
                        )
                        computed, commands, signatures = analysis(
                            repeat_db, estate, repeat_sid, formats, last_admx_dir
                        )
                        observations.append(
                            (
                                Counter(
                                    compute_fingerprint(c)
                                    for c in candidates_from_estate(estate, admx=admx)
                                ),
                                computed,
                                [c["exit_status"] for c in commands],
                                lifecycle.duplicate_fingerprint_count,
                                signatures,
                            )
                        )
                        denylist.update(database_strings(repeat_conn))
                a, b = observations
                return {
                    "identical": a == b and not any(a[2]) and not any(b[2]),
                    "fingerprints_added": sum((b[0] - a[0]).values()),
                    "fingerprints_removed": sum((a[0] - b[0]).values()),
                    "analysis_fields_changed": sum(a[4][k] != b[4][k] for k in a[4]),
                    "command_status_changes": sum(x != y for x, y in zip(a[2], b[2], strict=True)),
                }

            deterministic, record = measured(repeat, formats)
            report["determinism"] = {**record, **(deterministic or {"identical": False})}
        # Materialize the WAL before measuring/preserving the database file.
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        tables = []
        for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
            tables.append(
                {
                    "table": name,
                    "rows": conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0],
                }
            )
        report["scale"] = {
            "largest_tables": sorted(tables, key=lambda r: -r["rows"])[:10],
            "db_bytes": db.stat().st_size,
            "slowest_routes": [
                {"route_template": r["route_template"], "wall_seconds": r["wall_seconds"]}
                for r in sorted(report["web"], key=lambda r: -r["wall_seconds"])[:10]
            ],
            "slowest_commands": [
                {"name": r["name"], "wall_seconds": r["wall_seconds"]}
                for r in sorted(report["commands"], key=lambda r: -r["wall_seconds"])[:10]
            ],
        }
        report["web_5xx"] = [r for r in report["web"] if r["status_code"] >= 500]
        denylist.update(database_strings(conn))
        denylist.update(secrets)
        return report, denylist
    finally:
        conn.close()


def summary(report: dict[str, Any]) -> str:
    imported = [r for r in report["ingest"] if r["exit_status"] == 0]
    latest = imported[-1]["counts"] if imported else {}
    return (
        f"Exports: {len(imported)}/{len(report['ingest'])}; "
        f"GPOs: {int(latest.get('gpos', 0))}; SOMs: {int(latest.get('soms', 0))}; "
        f"settings: {int(latest.get('settings', 0))}\n"
        f"Web probes: {len(report['web'])}; 5xx: {len(report['web_5xx'])}; "
        f"secret leaks: {sum(report['redaction'].get('leaks_by_route_template', {}).values())}\n"
        f"Deterministic: {int(report['determinism']['identical'])}; "
        f"DB bytes: {int(report['scale']['db_bytes'])}\n"
    )


class SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> Any:
        # argparse's normal errors repeat user-supplied paths/arguments.
        raise ValueError("invalid arguments")


def detail_destination(path: Path) -> Path:
    """Resolve symlinks and reject any registered or enclosing git worktree."""
    resolved = path.resolve()
    repo = Path(__file__).resolve().parents[1]
    listing = subprocess.run(
        ["git", "-C", str(repo), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    )
    roots = [
        Path(line.removeprefix("worktree ")).resolve()
        for line in listing.stdout.splitlines()
        if line.startswith("worktree ")
    ]
    parent = resolved.parent
    while not parent.exists():
        parent = parent.parent
    enclosing = subprocess.run(
        ["git", "-C", str(parent), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if enclosing.returncode == 0:
        roots.append(Path(enclosing.stdout.strip()).resolve())
    if any(resolved.is_relative_to(root) for root in roots):
        raise ValueError("detail output must be outside git worktrees")
    return resolved


def aliases(a: Path, b: Path) -> bool:
    return a.resolve() == b.resolve() or (a.exists() and b.exists() and a.samefile(b))


def write_atomic(path: Path, rendered: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        temporary = Path(output.name)
        try:
            output.write(rendered)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = SafeParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--keep-db", type=Path)
    parser.add_argument("--detail", action="store_true", help="Collect private estate examples")
    parser.add_argument(
        "--detail-out", type=Path, help="Private detail JSON outside all git worktrees"
    )
    parser.add_argument("exports", type=Path, nargs="+")
    try:
        args = parser.parse_args(argv)
        if args.detail != bool(args.detail_out):
            raise ValueError("detail and detail-out must be supplied together")
        if args.detail_out:
            args.detail_out = detail_destination(args.detail_out)
        outputs = (
            [args.out]
            + ([args.keep_db] if args.keep_db else [])
            + ([args.detail_out] if args.detail_out else [])
        )
        for archive in args.exports:
            if any(aliases(output, archive) for output in outputs):
                raise ValueError("output aliases input")
        for index, output in enumerate(outputs):
            if any(aliases(output, other) for other in outputs[index + 1 :]):
                raise ValueError("output aliases another output")
        # No configured model or external audit sink may see estate data.
        environment = {k: v for k, v in os.environ.items() if not k.startswith("GPO_LENS_")}
        environment["GPO_LENS_ALLOWED_HOSTS"] = "testserver"
        with (
            patch.dict(os.environ, environment, clear=True),
            tempfile.TemporaryDirectory(prefix="gpo-calibration-") as temp,
        ):
            scratch = Path(temp)
            capture = Capture(source_formats())
            detail = Detail() if args.detail else None
            token = DETAIL.set(detail)
            try:
                with private_output(capture):
                    report, denylist = calibrate(args.exports, scratch)
            finally:
                DETAIL.reset(token)
            report["harness_warnings"] = capture.report()
            if args.keep_db:
                # Explicitly requested local evidence survives even a report
                # rejection. Never overwrite a DB or retain extracted inputs.
                with args.keep_db.open("xb") as dst, (scratch / "estate.sqlite3").open("rb") as src:
                    shutil.copyfileobj(src, dst)
            rendered = self_check(report, denylist)
            # The summary interpolates only counts and booleans from the
            # already checked report; its prose is fixed harness vocabulary.
            human = summary(report)
            if detail is not None:
                write_atomic(args.detail_out, json.dumps(detail.report(), indent=2) + "\n")
            write_atomic(args.out, rendered)
        print(human, end="")
        return 0
    except SanitizationError as exc:
        print(f"Sanitization refused at {exc.field}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(json.dumps(exception_info(exc)), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
