"""Shared CLI helpers: estate loading, JSON rendering, default DB path."""

from __future__ import annotations

import argparse
import builtins
import json
import sqlite3
import sys
from collections.abc import Sequence
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from gpo_lens import __version__, ingest, store
from gpo_lens.display import render_table
from gpo_lens.model import Estate
from gpo_lens.safe_output import safe_data, safe_text, secret_values

if TYPE_CHECKING:
    from gpo_lens.admx_parser import PolicyDefinitions

DEFAULT_DB = "./gpo-lens.sqlite3"

# Version of the machine-readable JSON output contract. Every `--json` payload
# is wrapped in a self-describing envelope carrying this number so downstream
# consumers can detect and adapt to contract evolution. Bump only on a
# breaking change to a `data` shape; additive fields keep the same version.
# See docs/spec/json-contract.md for the frozen shapes.
JSON_CONTRACT_VERSION = 1

# The current subcommand name, set once per invocation by the CLI entrypoint
# before dispatch. Used as the envelope `kind` so each payload is self-labelling.
_json_kind: str | None = None


def _set_json_kind(kind: str | None) -> None:
    """Record the active subcommand so `_render_json` can label its envelope."""
    global _json_kind
    _json_kind = kind


_output_secrets: ContextVar[tuple[str, ...]] = ContextVar("cli_output_secrets", default=())


def _begin_output(args: argparse.Namespace) -> Token[tuple[str, ...]]:
    """Read secret context for copied values; reset it after each invocation."""
    values: tuple[str, ...] = ()
    db = Path(args.db)
    command = getattr(args, "command", "")
    source_only = bool(getattr(args, "src", None) or getattr(args, "sample_dir", None))
    if command == "report" and getattr(args, "since", None) is not None:
        source_only = False
    if command not in {"serve", "ingest", "settings-diff"} and not source_only and db.is_file():
        from gpo_lens.exports import snapshot_secrets

        conn = sqlite3.connect(f"{db.resolve().as_uri()}?mode=ro", uri=True)
        try:
            if conn.execute("SELECT 1 FROM sqlite_master WHERE name='setting'").fetchone():
                values = snapshot_secrets(
                    conn, (row[0] for row in conn.execute("SELECT id FROM snapshot"))
                )
        finally:
            conn.close()
    return _output_secrets.set(values)


def _end_output(token: Token[tuple[str, ...]]) -> None:
    _output_secrets.reset(token)


def _add_secret_source(source: object) -> None:
    _output_secrets.set(tuple(set(_output_secrets.get()) | set(secret_values(source))))


def _project_output(value: object) -> object:
    return safe_data(value, secrets=_output_secrets.get())


def _safe_document(text: str) -> str:
    return safe_text(text, secrets=_output_secrets.get())


def _safe_print(
    *objects: object,
    sep: str = " ",
    end: str = "\n",
    file: TextIO | None = None,
    flush: bool = False,
) -> None:
    builtins.print(
        *(
            safe_text(obj, secrets=_output_secrets.get())
            if isinstance(obj, str)
            else safe_data(obj, secrets=_output_secrets.get())
            for obj in objects
        ),
        sep=sep,
        end=end,
        file=file,
        flush=flush,
    )


def _get_estate(args: argparse.Namespace) -> Estate:
    src = getattr(args, "src", None) or getattr(args, "sample_dir", None)
    if src:
        estate = ingest.load_estate(src)
        _add_secret_source(estate)
        return estate
    db = Path(args.db)
    if not db.exists():
        raise FileNotFoundError(f"Database not found: {db}")
    conn = sqlite3.connect(str(db))
    try:
        estate = store.load_estate(conn)
        _add_secret_source(estate)
        return estate
    finally:
        conn.close()


def _render_json(obj: object) -> None:
    """Print `obj` as the payload of the versioned JSON output envelope.

    The envelope is the frozen contract downstream tools consume: a stable
    `schema_version` + `kind` header with the command-specific payload under
    `data`. Volatile fields (`tool_version`, `generated_at`) are informational
    and must not be treated as part of the comparable shape.
    """
    envelope = {
        "schema_version": JSON_CONTRACT_VERSION,
        "kind": _json_kind,
        "tool_version": __version__,
        "generated_at": datetime.now(UTC).isoformat(),
        "data": obj,
    }
    print(json.dumps(safe_data(envelope, secrets=_output_secrets.get()), indent=2, default=str))


def _print_table(headers: list[str], rows: list[Sequence[str]]) -> None:
    projected = safe_data(
        [dict(zip(headers, row, strict=True)) for row in rows], secrets=_output_secrets.get()
    )
    print(render_table(headers, [[str(row[h]) for h in headers] for row in projected]))


def _get_admx(args: argparse.Namespace) -> PolicyDefinitions | None:
    """Resolve the ADMX resolver from CLI args or auto-detection.

    Priority:
    1. ``--admx-dir`` if provided and valid
    2. Auto-detect ``PolicyDefinitions`` in the export directory (``src``)
    3. ``None`` (no ADMX resolution)

    Prints a warning to stderr if ``--admx-dir`` is given but invalid.
    """
    from gpo_lens.admx_parser import find_admx_dir, parse_admx_dir

    def load(path: str | Path) -> PolicyDefinitions:
        admx = parse_admx_dir(path)
        if admx.skipped_files:
            print(
                f"Warning: {len(admx.skipped_files)} template files could not be read; "
                "ADMX names and coverage may be incomplete.",
                file=sys.stderr,
            )
        return admx

    admx_dir = getattr(args, "admx_dir", None)
    if admx_dir:
        if not Path(admx_dir).is_dir():
            print(
                f"Warning: --admx-dir not found or not a directory: {admx_dir}",
                file=sys.stderr,
            )
        else:
            return load(admx_dir)

    src = getattr(args, "src", None) or getattr(args, "sample_dir", None)
    if src:
        auto = find_admx_dir(src)
        if auto is not None:
            return load(auto)

    return None
