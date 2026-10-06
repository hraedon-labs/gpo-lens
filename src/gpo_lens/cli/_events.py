"""CLI subcommands for event store inspection and export."""

from __future__ import annotations

import argparse
import sqlite3
import sys

from gpo_lens.cli._helpers import _print_table, _project_output, _render_json
from gpo_lens.cli._helpers import _safe_print as print
from gpo_lens.events import query_events
from gpo_lens.sinks import HecSink, emit_events


def cmd_events(args: argparse.Namespace) -> int:
    conn = sqlite3.connect(args.db)
    try:
        rows = query_events(
            conn,
            since=getattr(args, "since", None),
            event_type=getattr(args, "event_type", None),
            limit=getattr(args, "limit", 1000),
        )
    finally:
        conn.close()
    if args.json:
        _render_json(rows)
    else:
        if not rows:
            print("No events found.")
            return 0
        _print_table(
            ["id", "timestamp", "event_type", "payload"],
            [[str(r["id"]), r["timestamp"], r["event_type"], str(r["payload"])] for r in rows],
        )
    return 0


def cmd_events_export(args: argparse.Namespace) -> int:
    conn = sqlite3.connect(args.db)
    try:
        events = query_events(
            conn,
            since=getattr(args, "since", None),
            limit=100000,
        )
    finally:
        conn.close()

    hec_sink = None
    if getattr(args, "sink", None) == "hec":
        hec_sink = HecSink.from_env()
        if hec_sink is None:
            print("Warning: HEC not configured via env vars", file=sys.stderr)

    ndjson_path = getattr(args, "ndjson", None)
    results = emit_events(
        _project_output(events),  # type: ignore[arg-type]
        ndjson_path=ndjson_path,
        hec_sink=hec_sink,
    )

    if ndjson_path and not results.get("ndjson"):
        print("Error: NDJSON export failed", file=sys.stderr)
        return 1
    return 0
