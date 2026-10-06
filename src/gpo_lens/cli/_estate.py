from __future__ import annotations

import argparse
import dataclasses
import sqlite3
from contextlib import ExitStack

from gpo_lens import ingest, queries, snapshot_diff, store
from gpo_lens.cli._helpers import _get_admx, _get_estate, _render_json
from gpo_lens.cli._helpers import _safe_print as print
from gpo_lens.collection_zip import collector_source


def cmd_summary(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    s = queries.estate_summary(estate)
    if args.json:
        _render_json(dataclasses.asdict(s))
    else:
        print(f"Domain: {s.domain}")
        print(f"GPOs: {s.gpo_count}  |  SOMs: {s.som_count}  |  WMI filters: {s.wmi_filter_count}")
        print(f"Settings: {s.total_settings}  |  Delegation entries: {s.total_delegation_entries}")
        print()
        issues = []
        if s.unlinked_count:
            issues.append(f"  Unlinked GPOs:           {s.unlinked_count}")
        if s.empty_count:
            issues.append(f"  Empty GPOs:              {s.empty_count}")
        if s.disabled_but_populated_count:
            issues.append(f"  Disabled-but-populated:  {s.disabled_but_populated_count}")
        if s.conflict_count:
            issues.append(f"  Setting conflicts:       {s.conflict_count}")
        if s.blocked_extension_count:
            issues.append(f"  Blocked extensions:      {s.blocked_extension_count}")
        if s.version_skew_count:
            issues.append(f"  Version skew:            {s.version_skew_count}")
        if s.ms16_072_vulnerable_count:
            issues.append(f"  MS16-072 vulnerable:     {s.ms16_072_vulnerable_count}")
        if s.cpassword_hit_count:
            issues.append(f"  cpassword hits (MS14-025): {s.cpassword_hit_count}")
        if s.loopback_gpo_count:
            issues.append(f"  Loopback GPOs:           {s.loopback_gpo_count}")
        if s.wmi_filtered_gpo_count:
            issues.append(f"  WMI-filtered GPOs:       {s.wmi_filtered_gpo_count}")
        if s.enforced_link_count:
            issues.append(f"  Enforced links:          {s.enforced_link_count}")
        if s.dangling_link_count:
            issues.append(f"  Dangling links:          {s.dangling_link_count}")
        if s.broken_ref_count:
            issues.append(f"  Broken references:       {s.broken_ref_count}")
        if s.admx_gap_count:
            issues.append(f"  ADMX gaps (raw reg keys): {s.admx_gap_count}")
        if issues:
            print("Hygiene & security:")
            for line in issues:
                print(line)
        else:
            print("No issues detected.")


def _latest_snapshot_before(conn: sqlite3.Connection, sid: int) -> int | None:
    row = conn.execute(
        "SELECT id FROM snapshot WHERE id < ? ORDER BY id DESC LIMIT 1", (sid,)
    ).fetchone()
    return row[0] if row else None


def _emit_ingest_events(
    conn: sqlite3.Connection,
    prev: int,
    sid: int,
    gpo_count: int,
) -> None:
    from gpo_lens.events import append_events as _append_events

    diff = snapshot_diff.snapshot_diff(conn, prev, sid)
    settings_changes = snapshot_diff.snapshot_settings_diff(conn, prev, sid)
    settings_by_gpo: dict[str, list[dict[str, str | None]]] = {}
    for sc in settings_changes:
        settings_by_gpo.setdefault(sc.gpo_id, []).append(
            {
                "cse": sc.cse,
                "identity": sc.identity,
                "gpo_name": sc.gpo_name,
                "old": sc.old_value,
                "new": sc.new_value,
            }
        )

    evs: list[tuple[str, dict[str, object]]] = []

    name_map: dict[str, str] = {}
    for row in conn.execute("SELECT id, name FROM gpo WHERE snapshot_id = ?", (sid,)):
        name_map[row[0]] = row[1]
    for row in conn.execute("SELECT id, name FROM gpo WHERE snapshot_id = ?", (prev,)):
        name_map.setdefault(row[0], row[1])

    for gpo_id in diff.gpos_added:
        evs.append(("gpo.created", {"gpo_id": gpo_id, "gpo_name": name_map.get(gpo_id, gpo_id)}))

    for gpo_id in diff.gpos_removed:
        evs.append(("gpo.deleted", {"gpo_id": gpo_id, "gpo_name": name_map.get(gpo_id, gpo_id)}))

    for gpo_id in diff.settings_changed:
        deltas = settings_by_gpo.get(gpo_id, [])
        total = len(deltas)
        capped = deltas[:100]
        payload: dict[str, object] = {
            "gpo_id": gpo_id,
            "gpo_name": name_map.get(gpo_id, gpo_id),
            "deltas": capped,
        }
        if total > 100:
            payload["truncated"] = True
            payload["total_count"] = total
        evs.append(("gpo.modified", payload))

    evs.append(
        (
            "ingest.summary",
            {
                "old_snapshot_id": prev,
                "new_snapshot_id": sid,
                "gpos_added": len(diff.gpos_added),
                "gpos_removed": len(diff.gpos_removed),
                "gpos_modified": len(diff.settings_changed),
                "gpo_count": gpo_count,
            },
        )
    )

    _append_events(conn, evs, commit=False)


def cmd_ingest(args: argparse.Namespace) -> None:
    with ExitStack() as sources:
        # Reject invalid uploads before opening or migrating any database.
        source = sources.enter_context(collector_source(args.sample_dir))
        estate = ingest.load_estate(source)
        conn = sqlite3.connect(args.db)
        try:
            store.init_db(conn)
            try:
                with conn:
                    sid = store.save_evaluated_estate(
                        conn, estate, admx=_get_admx(args), commit=False
                    )
                    prev = _latest_snapshot_before(conn, sid) if args.diff_latest else None
                    entries = snapshot_diff.snapshot_changelog(conn, prev, sid) if prev else []
                    if prev:
                        _emit_ingest_events(conn, prev, sid, len(estate.gpos))
                    # Detectors retain extracted SYSVOL through evaluation;
                    # cleanup failure rolls back before this transaction commits.
                    sources.close()
            except Exception as exc:
                raise RuntimeError("Import failed; nothing was imported.") from exc
            domain = estate.domain or "unknown"
            msg = f"{domain}, {len(estate.gpos)} GPOs, {len(estate.soms)} SOMs, snapshot={sid}"
            if args.json:
                out = {
                    "domain": domain,
                    "gpo_count": len(estate.gpos),
                    "som_count": len(estate.soms),
                    "snapshot_id": sid,
                }
                if args.diff_latest:
                    if prev:
                        out["changelog"] = [
                            {
                                "gpo_id": e.gpo_id,
                                "gpo_name": e.gpo_name,
                                "kind": e.kind,
                                "side": e.side,
                                "summary": e.summary,
                            }
                            for e in entries
                        ]
                _render_json(out)
            else:
                print(msg)
                if args.diff_latest:
                    if prev:
                        if entries:
                            print("\nChanges since previous snapshot:")
                            for e in entries:
                                prefix = "[DETAIL]" if e.kind == "settings_detail" else "[META]"
                                print(f"  {prefix} {e.gpo_name} — {e.summary}")
                                for sc in e.setting_changes:
                                    print(
                                        f"    [{sc.side}/{sc.cse}] {sc.identity}: {sc.change_type}"
                                    )
                        else:
                            print("\nNo changes since previous snapshot.")
                    else:
                        print("\nNo previous snapshot to diff against.")
        finally:
            conn.close()
