"""CLI subcommand: trends -- posture-over-time from snapshot history."""

from __future__ import annotations

import argparse
import sqlite3

from gpo_lens.cli._helpers import _print_table, _render_json
from gpo_lens.cli._helpers import _safe_print as print
from gpo_lens.trend import changes_only, compute_trend


def cmd_trends(args: argparse.Namespace) -> None:
    conn = sqlite3.connect(args.db)
    try:
        points = compute_trend(conn)
    finally:
        conn.close()

    if getattr(args, "changes_only", False):
        points = changes_only(points)

    if args.json:
        _render_json(
            [
                {
                    "snapshot_id": p.snapshot_id,
                    "taken_at": p.taken_at,
                    "gpo_count": p.gpo_count,
                    "danger_finding_count": p.danger_finding_count,
                    "cpassword_hit_count": p.cpassword_hit_count,
                    "ms16_072_vulnerable_count": p.ms16_072_vulnerable_count,
                    "version_skew_count": p.version_skew_count,
                    "broken_ref_count": p.broken_ref_count,
                    "unlinked_count": p.unlinked_count,
                    "empty_count": p.empty_count,
                    "total_settings": p.total_settings,
                    "coverage_gap_count": p.coverage_gap_count,
                }
                for p in points
            ]
        )
    else:
        if not points:
            print("No snapshots found.")
            return
        _print_table(
            [
                "Snapshot ID",
                "Date",
                "GPOs",
                "Dangers",
                "Cpassword",
                "MS16-072",
                "Skew",
                "Broken Refs",
                "Coverage Gaps",
            ],
            [
                [
                    str(p.snapshot_id),
                    p.taken_at or "\u2014",
                    str(p.gpo_count),
                    str(p.danger_finding_count),
                    str(p.cpassword_hit_count),
                    str(p.ms16_072_vulnerable_count),
                    str(p.version_skew_count),
                    str(p.broken_ref_count),
                    str(p.coverage_gap_count),
                ]
                for p in points
            ],
        )
