"""Calibrate copied estates without exposing their contents.

Run with the project's web/dev extras installed. This script is deliberately
outside the installed package. All input, CLI output, HTTP bodies and exception
messages remain private. Only counts and source-verified identifiers cross the
report boundary; the final substring gate applies to JSON *and* stdout.

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
import sys
import tempfile
import time
import tracemalloc
import warnings
import zipfile
from collections import Counter
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from functools import cache, partial
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import quote, unquote

from defusedxml import ElementTree as ET

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
def source_formats() -> list[tuple[re.Pattern[str], str]]:
    """Allow only complete, statically extracted gpo-lens message formats."""
    formats: list[tuple[re.Pattern[str], str]] = []
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
            template = normalize_message("".join(p if p is not None else "<value>" for p in parts))
            formats.append((pattern, template))
    return formats


class Capture(logging.Handler):
    def __init__(self, formats: list[tuple[re.Pattern[str], str]]) -> None:
        super().__init__(logging.WARNING)
        self.formats = formats
        self.counts: Counter[str] = Counter()
        self.other = 0
        self.exceptions: list[dict[str, object]] = []

    def message(self, message: str) -> None:
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

    def report(self) -> dict[str, object]:
        return {"templates": dict(sorted(self.counts.items())), "other_warnings": self.other}


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
                    side_effect=lambda msg, *a, **kw: capture.message(str(msg)),
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


def measured(
    fn: Callable[[], Any], formats: list[tuple[re.Pattern[str], str]]
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
    record.update(wall_seconds=round(time.perf_counter() - started, 6), warnings=capture.report())
    record["exceptions"].extend(capture.exceptions)
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
    """Literal, case-insensitive substring gate, with no implicit exceptions.

    Paths use numeric dictionary positions so an injected key cannot leak via
    the rejection diagnostic. Scan serialized AND decoded leaves (JSON escaping
    must not hide a planted string); check keys and non-string scalar encodings.
    """
    needles = {s.casefold() for s in denylist if len(s) >= 4}

    def check(value: object, path: str) -> None:
        if isinstance(value, dict):
            for index, (key, child) in enumerate(value.items()):
                check(key, f"{path}[key:{index}]")
                check(child, f"{path}[{index}]")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                check(child, f"{path}[{index}]")
        else:
            encoded = json.dumps(value, ensure_ascii=True)
            texts = [encoded.casefold()]
            if isinstance(value, str):
                texts.append(value.casefold())
            if any(needle in text for needle in needles for text in texts):
                raise SanitizationError(path)

    check(report, "$")
    serialized = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if any(needle in serialized.casefold() for needle in needles):
        raise SanitizationError("$")
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
                except (ValueError, UnicodeError):
                    pass
            elif target.suffix.lower() == ".xml":
                try:
                    tree = ET.parse(target)
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
                except (ET.ParseError, ValueError, UnicodeError):
                    pass
    reports = list(dest.rglob("AllGPOs.xml"))
    if len(reports) != 1:
        raise ValueError("primary report count")
    return reports[0].parent


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


def estate_counts(estate: Estate, facts: InputFacts) -> dict[str, object]:
    settings = [s for g in estate.gpos for s in g.settings]
    cse = Counter(CSE_NAMES[s.cse.lower()] for s in settings if s.cse.lower() in CSE_NAMES)
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
        "principals_resolved": sum(p.resolved for p in estate.principals.values()),
        "principals_unresolved": sum(not p.resolved for p in estate.principals.values()),
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
    with sqlite3.connect(db) as conn:
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
        limiter.max_requests = 1000000
    with sqlite3.connect(db) as conn:
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
                            else ("md", "csv", "json")
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
                        sqlite3.connect(db) as original_conn,
                        sqlite3.connect(sandbox) as probe_conn,
                    ):
                        original_conn.backup(probe_conn)
                    app.state.db_path = str(sandbox)
                try:
                    response, record = measured(request, formats)
                    if method == "POST" and denylist is not None:
                        with sqlite3.connect(sandbox) as probe_conn:
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
                records.append(record)
    return records, dict(sorted(leaks.items()))


def calibrate(archives: list[Path], scratch: Path) -> tuple[dict[str, Any], set[str]]:
    formats = source_formats()
    db = scratch / "estate.sqlite3"
    conn = sqlite3.connect(db)
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
    try:
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
                record.update(snapshot_id=sid, counts=estate_counts(estate, facts))
                admx_dir = find_admx_dir(src) or empty_admx
                admx, admx_record = measured(partial(parse_admx_dir, admx_dir), formats)
                admx_record["name"] = "admx-coverage"
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
                    with sqlite3.connect(repeat_db) as repeat_conn:
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
        f"GPOs: {latest.get('gpos', 0)}; SOMs: {latest.get('soms', 0)}; "
        f"settings: {latest.get('settings', 0)}\n"
        f"Web probes: {len(report['web'])}; 5xx: {len(report['web_5xx'])}; "
        f"secret leaks: {sum(report['redaction'].get('leaks_by_route_template', {}).values())}\n"
        f"Deterministic: {int(report['determinism']['identical'])}; "
        f"DB bytes: {report['scale']['db_bytes']}\n"
    )


class SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> Any:
        # argparse's normal errors repeat user-supplied paths/arguments.
        raise ValueError("invalid arguments")


def main(argv: list[str] | None = None) -> int:
    parser = SafeParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--keep-db", type=Path)
    parser.add_argument("exports", type=Path, nargs="+")
    try:
        args = parser.parse_args(argv)
        for archive in args.exports:
            if args.out.resolve() == archive.resolve() or (
                args.out.exists() and archive.exists() and args.out.samefile(archive)
            ):
                raise ValueError("output aliases input")
        if args.keep_db and args.out.resolve() == args.keep_db.resolve():
            raise ValueError("output aliases database")
        # No configured model or external audit sink may see estate data.
        environment = {k: v for k, v in os.environ.items() if not k.startswith("GPO_LENS_")}
        environment["GPO_LENS_ALLOWED_HOSTS"] = "testserver"
        with (
            patch.dict(os.environ, environment, clear=True),
            tempfile.TemporaryDirectory(prefix="gpo-calibration-") as temp,
        ):
            scratch = Path(temp)
            capture = Capture(source_formats())
            with private_output(capture):
                report, denylist = calibrate(args.exports, scratch)
            report["harness_warnings"] = capture.report()
            if args.keep_db:
                # Explicitly requested local evidence survives even a report
                # rejection. Never overwrite a DB or retain extracted inputs.
                with args.keep_db.open("xb") as dst, (scratch / "estate.sqlite3").open("rb") as src:
                    shutil.copyfileobj(src, dst)
            rendered = self_check(report, denylist)
            human = summary(report)
            self_check(human, denylist)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=args.out.parent, delete=False
            ) as output:
                output.write(rendered)
                temporary = Path(output.name)
            try:
                temporary.replace(args.out)
            finally:
                temporary.unlink(missing_ok=True)
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
