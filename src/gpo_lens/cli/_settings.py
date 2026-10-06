"""CLI subcommands for GPO settings inspection (search, who-sets, settings-dump, etc.)."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from gpo_lens import queries
from gpo_lens.cli._helpers import (
    _add_secret_source,
    _get_admx,
    _get_estate,
    _print_table,
    _render_json,
)
from gpo_lens.cli._helpers import _safe_print as print
from gpo_lens.display import render_settings_diff


def cmd_who_sets(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.who_sets(estate, args.term)
    name_map = estate.gpo_names
    if args.json:
        _render_json(
            [
                {
                    "gpo_id": s.gpo_id,
                    "gpo_name": name_map.get(s.gpo_id, ""),
                    "cse": s.cse,
                    "identity": s.identity,
                    "display_value": s.display_value,
                }
                for s in result
            ]
        )
    else:
        _print_table(
            ["gpo_id", "gpo_name", "cse", "identity", "display_value"],
            [
                [s.gpo_id, name_map.get(s.gpo_id, ""), s.cse, s.identity, s.display_value]
                for s in result
            ],
        )


def cmd_conflicts(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.conflicts(estate)
    if args.json:
        _render_json(
            [
                {
                    "cse": c.cse,
                    "side": c.side,
                    "identity": c.identity,
                    "display_name": c.display_name,
                    "entries": [{"gpo_id": gid, "display_value": val} for gid, val in c.entries],
                }
                for c in result
            ]
        )
    else:
        rows: list[Sequence[str]] = []
        for c in result:
            for gid, val in c.entries:
                rows.append([c.cse, c.side, c.identity, gid, val])
        _print_table(["cse", "side", "identity", "gpo_id", "value"], rows)


def cmd_search(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    results = queries.search(estate, args.term, scope=args.scope)
    if args.json:
        _render_json(
            [{"gpo_id": r.gpo_id, "field": r.match_field, "detail": r.detail} for r in results]
        )
    else:
        for r in results:
            print(f"{r.gpo_id}\t{r.gpo_name}\t{r.match_field}\t{r.detail}")


def cmd_show(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    target = args.gpo_id
    gpo = None
    for g in estate.gpos:
        if g.id == target or g.name == target:
            gpo = g
            break
    if gpo is None:
        print(f"GPO {target} not found", file=sys.stderr)
        return
    if args.json or args.format == "json":
        _render_json(
            {
                "id": gpo.id,
                "name": gpo.name,
                "domain": gpo.domain,
                "description": gpo.description,
                "computer_enabled": gpo.computer_enabled,
                "user_enabled": gpo.user_enabled,
                "links": [
                    {
                        "som_name": link.som_name,
                        "som_path": link.som_path,
                        "enabled": link.link_enabled,
                        "enforced": link.enforced,
                    }
                    for link in gpo.links
                ],
                "settings_count": len(gpo.settings),
                "delegation_count": len(gpo.delegation),
            }
        )
    else:
        print(f"GPO: {gpo.name} ({gpo.id})")
        print(f"  Domain: {gpo.domain}")
        if gpo.description:
            print(f"  Description: {gpo.description}")
        for s in gpo.settings[:100]:
            print(f"  [{s.cse}] {s.side}/{s.identity}: {s.display_value}")
        if len(gpo.settings) > 100:
            print(f"  ... ({len(gpo.settings) - 100} more settings)")


def cmd_settings_at(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.settings_at_som(estate, args.som_path)
    caveats = queries.scope_caveats(estate, args.som_path)
    if args.json:
        _render_json(
            {
                "settings": [
                    {
                        "cse": r.cse,
                        "side": r.side,
                        "identity": r.identity,
                        "display_name": r.display_name,
                        "display_value": r.display_value,
                        "winner_gpo_id": r.winner_gpo_id,
                        "winner_gpo_name": r.winner_gpo_name,
                        "overridden_by": [{"gpo_name": n, "value": v} for n, v in r.overridden_by],
                        "enforced": r.enforced,
                    }
                    for r in result
                ],
                "caveats": caveats,
            }
        )
    else:
        if not result:
            print(f"No effective settings at {args.som_path}")
            return
        if caveats:
            print("\n  \u26a0 SCOPE CAVEATS:")
            for c in caveats:
                print(f"    {c}")
            print("    Effective settings may differ — scoping mechanisms not simulated.\n")
        by_gpo: dict[str, list[queries.EffectiveSetting]] = {}
        for r in result:
            by_gpo.setdefault(r.winner_gpo_name, []).append(r)
        for gpo_name, settings in by_gpo.items():
            print(f"\n  [{gpo_name}]")
            for s in settings:
                enforced_flag = " [ENFORCED]" if s.enforced else ""
                print(
                    f"    [{s.cse}] {s.side}/{s.identity}{enforced_flag}\n"
                    f"      {s.display_name}: {s.display_value}"
                )
                if s.overridden_by:
                    for o_name, o_val in s.overridden_by:
                        print(f"      (overridden: {o_name} = {o_val})")


def cmd_som_conflicts(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.som_conflicts(estate, args.som_path)
    if args.json:
        _render_json(
            [
                {
                    "som_path": c.som_path,
                    "cse": c.cse,
                    "side": c.side,
                    "identity": c.identity,
                    "display_name": c.display_name,
                    "winner": c.winner,
                    "entries": [
                        {"gpo_name": name, "value": value, "status": status}
                        for name, value, status in c.entries
                    ],
                }
                for c in result
            ]
        )
    else:
        rows: list[Sequence[str]] = []
        for c in result:
            for name, value, status in c.entries:
                rows.append([c.som_path, c.cse, c.side, c.identity, name, value, status])
        _print_table(
            ["som_path", "cse", "side", "identity", "gpo_name", "value", "status"],
            rows,
        )


def cmd_precedence_conflicts(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.precedence_conflicts(estate)
    loopback_map = queries.loopback_awareness(estate)
    if args.json:
        _render_json(
            [
                {
                    "som_path": som.path,
                    "som_name": som.name,
                    "conflicts": [
                        {
                            "cse": c.cse,
                            "side": c.side,
                            "identity": c.identity,
                            "display_name": c.display_name,
                            "winner": c.winner,
                            "entries": [
                                {"gpo_name": n, "value": v, "status": s} for n, v, s in c.entries
                            ],
                        }
                        for c in conflicts
                    ],
                }
                for som, conflicts in result
            ]
        )
    else:
        if loopback_map:
            print("\n  \u26a0 LOOPBACK CAVEAT:")
            for gid, mode in sorted(loopback_map.items()):
                gpo = estate.gpo_by_id(gid)
                gpo_name = gpo.name if gpo else gid
                print(f"    {gpo_name}: loopback={mode}")
            print("    Precedence conflicts on the User side may be affected by")
            print("    loopback processing (merge/replace) on affected computers.\n")
        rows: list[Sequence[str]] = []
        for som, conflicts in result:
            for c in conflicts:
                for name, value, status in c.entries:
                    rows.append([som.path, c.cse, c.side, c.identity, name, value, status])
        _print_table(
            ["som_path", "cse", "side", "identity", "gpo_name", "value", "status"],
            rows,
        )


def cmd_settings_dump(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    results = queries.settings_dump(
        estate,
        side=getattr(args, "side", None),
        cse=getattr(args, "cse", None),
        gpo_name=getattr(args, "gpo_name", None),
    )
    if args.json:
        _render_json(
            [
                {
                    "gpo_id": r.gpo_id,
                    "gpo_name": r.gpo_name,
                    "side": r.side,
                    "cse": r.cse,
                    "identity": r.identity,
                    "display_name": r.display_name,
                    "display_value": r.display_value,
                    "from_disabled_side": r.from_disabled_side,
                    "source_state": r.source_state,
                }
                for r in results
            ]
        )
    else:
        _print_table(
            ["gpo_id", "gpo_name", "side", "cse", "identity", "value"],
            [[r.gpo_id, r.gpo_name, r.side, r.cse, r.identity, r.display_value] for r in results],
        )


def cmd_settings_diff(args: argparse.Namespace) -> None:
    result = queries.settings_diff(
        args.file_a,
        args.file_b,
        side=getattr(args, "side", None),
        cse=getattr(args, "cse", None),
        gpo_id=getattr(args, "gpo_id", None),
    )
    _add_secret_source(result)
    skipped = getattr(result, "skipped_count", 0)
    if args.json:
        _render_json(
            {
                "skipped": skipped,
                "changes": [
                    {
                        "gpo_id": r.gpo_id,
                        "gpo_name": r.gpo_name,
                        "side": r.side,
                        "cse": r.cse,
                        "identity": r.identity,
                        "display_name": r.display_name,
                        "change_type": r.change_type,
                        "old_value": r.old_value,
                        "new_value": r.new_value,
                    }
                    for r in result
                ],
            }
        )
    else:
        if not result:
            print("No differences found.")
        else:
            added = [r for r in result if r.change_type == "added"]
            removed = [r for r in result if r.change_type == "removed"]
            modified = [r for r in result if r.change_type == "modified"]
            print(
                f"Settings Diff: {len(added)} added, "
                f"{len(removed)} removed, {len(modified)} modified"
            )
            print()
            print(render_settings_diff(added, removed, modified), end="")
        if skipped:
            print(f"\n({skipped} row(s) skipped due to missing/invalid fields)")


def cmd_admx_gaps(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    admx = _get_admx(args)
    result = queries.admx_gaps(estate, admx)
    if args.json:
        _render_json(
            [
                {
                    "gpo_id": r.gpo_id,
                    "gpo_name": r.gpo_name,
                    "side": r.side,
                    "identity": r.identity,
                    "key_path": r.key_path,
                    "value_name": r.value_name,
                }
                for r in result
            ]
        )
    else:
        if not result:
            print("No ADMX gaps found.")
        else:
            _print_table(
                ["gpo_id", "gpo_name", "side", "key_path", "value_name"],
                [[r.gpo_id, r.gpo_name, r.side, r.key_path, r.value_name] for r in result],
            )


def cmd_admx_coverage(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    admx = _get_admx(args)
    report = queries.admx_coverage(estate, admx)
    if args.json:
        import dataclasses

        _render_json(
            {
                "summary": dataclasses.asdict(report.summary),
                "referenced": [dataclasses.asdict(e) for e in report.referenced],
                "unreferenced": [dataclasses.asdict(e) for e in report.unreferenced],
                "gaps": [dataclasses.asdict(e) for e in report.gaps],
                "skipped_files": [dataclasses.asdict(e) for e in report.skipped_files],
            }
        )
    else:
        s = report.summary
        print("ADMX Coverage")
        print("=" * 60)
        print(f"  Total policies: {s.total_policies}")
        print(f"  Referenced:     {s.referenced_policies}")
        print(f"  Unreferenced:   {s.unreferenced_policies}")
        print(f"  Gap settings:   {s.gap_count}")
        if report.skipped_files:
            print(f"  {s.unreadable_file_count} template files could not be read:")
            for skipped in report.skipped_files:
                print(f"    {skipped.filename}: {skipped.reason_class}")
        print()
        if report.gaps:
            print("--- Gap Settings (no ADMX match) ---")
            _print_table(
                ["GPO", "Side", "Key Path", "Value Name"],
                [
                    [e.referenced_gpos, e.class_scope, e.registry_key, e.value_name]
                    for e in report.gaps
                ],
            )
            print()
        if report.referenced:
            print("--- Referenced Policies ---")
            _print_table(
                ["Policy Name", "Display Name", "GPOs"],
                [[e.policy_name, e.display_name, e.referenced_gpos] for e in report.referenced],
            )
