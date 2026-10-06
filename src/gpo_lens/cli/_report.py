"""CLI subcommand for generating estate reports (Markdown/HTML)."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from gpo_lens import snapshot_diff, store
from gpo_lens.cli._helpers import _add_secret_source, _get_admx, _get_estate, _safe_document
from gpo_lens.cli._helpers import _safe_print as print


def cmd_report(args: argparse.Namespace) -> int:
    # `report` produces a human-readable document (md/html), not part of the
    # machine-readable JSON contract. Refuse --json loudly rather than silently
    # emitting Markdown that a consumer would try (and fail) to parse as JSON.
    if getattr(args, "json", False):
        print(
            "report produces human-readable documents (--format md|html), not JSON. "
            "For machine-readable output use 'summary --json' (estate snapshot), "
            "'doctor --json' (findings), or 'settings-dump --json' (per-setting rows).",
            file=sys.stderr,
        )
        return 2
    estate = _get_estate(args)
    baseline = None
    changelog_entries = None
    max_settings = getattr(args, "max_settings", 50)
    admx_dir = getattr(args, "admx_dir", None)
    if admx_dir and not args.baseline:
        print("Warning: --admx-dir has no effect without --baseline", file=sys.stderr)
    if args.baseline:
        baseline_path = Path(args.baseline)
        if not baseline_path.exists():
            print(f"Baseline file not found: {baseline_path}", file=sys.stderr)
            return 1
        try:
            data = json.loads(baseline_path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            print(f"Baseline file is not valid JSON: {exc}", file=sys.stderr)
            return 1
        from gpo_lens.queries import BaselineSetting, baseline_diff

        baseline_settings = [
            BaselineSetting(
                side=entry.get("side", ""),
                cse=entry.get("cse", ""),
                identity=entry.get("identity", ""),
                display_name=entry.get("display_name", ""),
                expected_value=entry.get("expected_value", ""),
            )
            for entry in data
        ]

        _add_secret_source(baseline_settings)
        admx = _get_admx(args)
        baseline = baseline_diff(estate, baseline_settings, admx)
    if args.since is not None:
        db = Path(args.db)
        if not db.exists():
            print(f"Database not found: {db}", file=sys.stderr)
            return 1
        conn = sqlite3.connect(str(db))
        try:
            snapshots = store.list_snapshots(conn)
            if not snapshots:
                print("No snapshots found in database.", file=sys.stderr)
                return 1
            latest = snapshots[0][0]
            changelog_entries = snapshot_diff.snapshot_changelog(conn, args.since, latest)
        finally:
            conn.close()

    from gpo_lens.report import generate_report

    fmt = args.format
    output = getattr(args, "output", None)
    text = _safe_document(
        generate_report(
            estate,
            baseline=baseline,
            changelog_entries=changelog_entries,
            format=fmt,
            max_settings=max_settings,
        )
    )
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"Report written to {output}")
    else:
        print(text)
    return 0
