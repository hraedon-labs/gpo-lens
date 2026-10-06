"""CLI subcommands for snapshot diffing, changelog, and baseline comparison."""

from __future__ import annotations

import argparse
import dataclasses
import sqlite3

from gpo_lens import ingest, queries, snapshot_diff, store
from gpo_lens.cli._helpers import (
    _add_secret_source,
    _get_admx,
    _get_estate,
    _print_table,
    _render_json,
)
from gpo_lens.cli._helpers import _safe_print as print


def cmd_diff(args: argparse.Namespace) -> None:
    conn = sqlite3.connect(args.db)
    try:
        diff = snapshot_diff.snapshot_diff(conn, args.snapshot_a, args.snapshot_b)
    finally:
        conn.close()
    if args.json:

        def _asdict(obj: object) -> object:
            if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
                return dataclasses.asdict(obj)
            return obj

        _render_json(
            {
                "gpos_added": diff.gpos_added,
                "gpos_removed": diff.gpos_removed,
                "settings_changed": diff.settings_changed,
                "links_changed": diff.links_changed,
                "delegation_changed": diff.delegation_changed,
                "version_skew_changed": diff.version_skew_changed,
                "metadata_changes": [_asdict(m) for m in diff.metadata_changes],
                "wmi_filter_changes": [_asdict(m) for m in diff.wmi_filter_changes],
                "enabled_flips": [_asdict(m) for m in diff.enabled_flips],
            }
        )
    else:
        if diff.gpos_added:
            print(f"GPOs added: {', '.join(diff.gpos_added)}")
        if diff.gpos_removed:
            print(f"GPOs removed: {', '.join(diff.gpos_removed)}")
        if diff.settings_changed:
            print(f"Settings changed: {', '.join(diff.settings_changed)}")
        if diff.links_changed:
            print(f"Links changed: {', '.join(diff.links_changed)}")
        if diff.delegation_changed:
            print(f"Delegation changed: {', '.join(diff.delegation_changed)}")
        if diff.version_skew_changed:
            print(f"Version skew changed: {', '.join(diff.version_skew_changed)}")
        for m in diff.metadata_changes:
            print(f"Metadata: {m.gpo_id}.{m.field}: {m.old_value} -> {m.new_value}")
        for m in diff.wmi_filter_changes:
            print(f"WMI filter: {m.gpo_id}: {m.old_value} -> {m.new_value}")
        for m in diff.enabled_flips:
            print(f"Enabled flip: {m.gpo_id}.{m.field}: {m.old_value} -> {m.new_value}")
        if not any(
            [
                diff.gpos_added,
                diff.gpos_removed,
                diff.settings_changed,
                diff.links_changed,
                diff.delegation_changed,
                diff.version_skew_changed,
                diff.metadata_changes,
                diff.wmi_filter_changes,
                diff.enabled_flips,
            ]
        ):
            print("No differences found.")


def cmd_diff_settings(args: argparse.Namespace) -> None:
    conn = sqlite3.connect(args.db)
    try:
        changes = snapshot_diff.snapshot_settings_diff(
            conn,
            args.snapshot_a,
            args.snapshot_b,
            gpo_id=args.gpo_id,
            side=args.side,
            cse=args.cse,
        )
    finally:
        conn.close()
    if args.json:
        _render_json([dataclasses.asdict(c) for c in changes])
    else:
        if not changes:
            print("No setting differences found.")
            return
        _print_table(
            ["GPO", "Side", "CSE", "Identity", "Change", "Old", "New"],
            [
                [
                    c.gpo_name,
                    c.side,
                    c.cse,
                    c.identity,
                    c.change_type,
                    c.old_value or "",
                    c.new_value or "",
                ]
                for c in changes
            ],
        )


def cmd_changelog(args: argparse.Namespace) -> None:
    conn = sqlite3.connect(args.db)
    entries = snapshot_diff.snapshot_changelog(conn, args.snapshot_a, args.snapshot_b)
    conn.close()
    if args.gpo_id:
        entries = [e for e in entries if e.gpo_id == args.gpo_id]
    if args.side:
        side_lower = args.side.lower()
        entries = [e for e in entries if e.side and e.side.lower() == side_lower]
    if args.json:

        def _sc_asdict(sc: snapshot_diff.SnapshotSettingChange) -> dict[str, object]:
            return dataclasses.asdict(sc)

        def _vc_asdict(vc: snapshot_diff.VersionChangeLog | None) -> dict[str, object] | None:
            if vc is None:
                return None
            return dataclasses.asdict(vc)

        _render_json(
            [
                {
                    "gpo_id": e.gpo_id,
                    "gpo_name": e.gpo_name,
                    "kind": e.kind,
                    "side": e.side,
                    "summary": e.summary,
                    "version_change": _vc_asdict(e.version_change),
                    "setting_changes": [_sc_asdict(sc) for sc in e.setting_changes],
                }
                for e in entries
            ]
        )
    else:
        if not entries:
            print("No changes found between snapshots.")
            return
        for e in entries:
            prefix = "[DETAIL]" if e.kind == "settings_detail" else "[META]"
            print(f"{prefix} {e.gpo_name} ({e.gpo_id}) — {e.summary}")
            for sc in e.setting_changes:
                print(f"  [{sc.side}/{sc.cse}] {sc.identity}: {sc.change_type}")
                if sc.old_value or sc.new_value:
                    print(f"    {sc.old_value or ''} -> {sc.new_value or ''}")


def cmd_snapshots(args: argparse.Namespace) -> None:
    conn = sqlite3.connect(args.db)
    try:
        result = store.list_snapshots(conn)
    finally:
        conn.close()
    if args.json:
        _render_json(
            [{"id": sid, "domain": domain, "taken_at": taken} for sid, domain, taken in result]
        )
    else:
        _print_table(
            ["id", "domain", "taken_at"],
            [[str(sid), domain, str(taken)] for sid, domain, taken in result],
        )


def cmd_baseline_diff(args: argparse.Namespace) -> None:
    from pathlib import Path as _Path

    from gpo_lens.ingest import load_baseline_from_zip

    estate = _get_estate(args)
    baseline_src = _Path(args.baseline_dir)
    if baseline_src.suffix.lower() == ".zip":
        baseline_gpos = load_baseline_from_zip(baseline_src)
        from gpo_lens.model import Estate as _Estate

        baseline_estate = _Estate(gpos=baseline_gpos)
    else:
        baseline_estate = ingest.load_estate(baseline_src)
    _add_secret_source(baseline_estate)
    baseline = queries.load_baseline_from_estate(baseline_estate)

    admx = _get_admx(args)

    results = queries.baseline_diff(estate, baseline, admx)
    if args.json:
        _render_json([dataclasses.asdict(r) for r in results])
    else:
        if not results:
            print("No baseline settings to compare.")
            return
        drift = [r for r in results if r.status == "drift"]
        missing = [r for r in results if r.status == "missing"]
        extra = [r for r in results if r.status == "extra"]
        compliant = [r for r in results if r.status == "compliant"]

        print("Baseline Diff")
        print("=" * 60)
        print(
            f"  Compliant: {len(compliant)}  |  Drift: {len(drift)}  |  "
            f"Missing: {len(missing)}  |  Extra: {len(extra)}"
        )
        print()

        for group_name, group in [("DRIFT", drift), ("MISSING", missing), ("EXTRA", extra)]:
            if group:
                print(f"--- {group_name} ---")
                for r in group:
                    label = r.admx_name or r.display_name or r.identity
                    if r.status == "drift":
                        print(f"  [{r.cse}] {r.side}/{label}")
                        print(f"    expected: {r.expected_value}")
                        print(f"    actual:   {r.actual_value}  (GPO: {r.gpo_id})")
                    elif r.status == "missing":
                        print(f"  [{r.cse}] {r.side}/{label}")
                        print(f"    expected: {r.expected_value}")
                    else:
                        print(f"  [{r.cse}] {r.side}/{label}")
                        print(f"    actual: {r.actual_value}  (GPO: {r.gpo_id})")
                print()


def cmd_golden_diff(args: argparse.Namespace) -> None:
    from pathlib import Path as _Path

    from gpo_lens.ingest import load_baseline_from_zip
    from gpo_lens.model import Estate as _Estate

    live_estate = _get_estate(args)
    golden_src = _Path(args.golden_dir)
    if golden_src.suffix.lower() == ".zip":
        golden_gpos = load_baseline_from_zip(golden_src)
        golden_estate = _Estate(gpos=golden_gpos)
    else:
        golden_estate = ingest.load_estate(golden_src)

    admx = _get_admx(args)
    _add_secret_source(golden_estate)
    results = queries.golden_diff(live_estate, golden_estate, admx)
    live_names = {g.name.lower() for g in live_estate.gpos}
    golden_names = {g.name.lower() for g in golden_estate.gpos}
    summary = queries.golden_diff_summary(
        results,
        matched_gpo_count=len(live_names & golden_names),
    )

    if args.json:
        _render_json(
            {
                "summary": dataclasses.asdict(summary),
                "entries": [dataclasses.asdict(r) for r in results],
            }
        )
    else:
        print("Golden-Backup Diff")
        print("=" * 60)
        print(
            f"  GPOs matched: {summary.gpos_matched}  |  "
            f"Added: {summary.gpos_added}  |  Removed: {summary.gpos_removed}"
        )
        print(
            f"  Settings — Compliant: {summary.settings_compliant}  |  "
            f"Changed: {summary.settings_changed}  |  "
            f"Added: {summary.settings_added}  |  Removed: {summary.settings_removed}"
        )
        print()

        non_compliant = [r for r in results if r.status != "compliant"]
        if not non_compliant:
            print("No drift detected — estate matches golden backup.")
            return

        for r in non_compliant:
            label = r.admx_name or r.display_name or r.identity
            if r.status == "gpo_removed":
                print(f"  [GPO REMOVED] {r.gpo_name}")
            elif r.status == "gpo_added":
                print(f"  [GPO ADDED] {r.gpo_name}")
            elif r.status == "changed":
                print(f"  [{r.cse}] {r.side}/{label}  (GPO: {r.gpo_name})")
                print(f"    golden: {r.golden_value}")
                print(f"    live:   {r.live_value}")
            elif r.status == "removed":
                print(f"  [{r.cse}] {r.side}/{label}  (GPO: {r.gpo_name})")
                print(f"    golden: {r.golden_value}  (removed from live)")
            elif r.status == "added":
                print(f"  [{r.cse}] {r.side}/{label}  (GPO: {r.gpo_name})")
                print(f"    live: {r.live_value}  (new since golden)")
        print()
