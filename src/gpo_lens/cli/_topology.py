"""CLI subcommands for OU topology analysis (effective-gpos, conflicts, settings-at)."""

from __future__ import annotations

import argparse
import sys

from gpo_lens import queries
from gpo_lens.cli._helpers import _get_estate, _print_table, _render_json
from gpo_lens.cli._helpers import _safe_print as print


def cmd_som(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.som_effective_gpos(estate, args.som_path)
    if args.json:
        _render_json(
            [
                {
                    "gpo_id": r.gpo_id,
                    "gpo_name": r.gpo_name,
                    "order": r.order,
                    "enabled": r.enabled,
                    "enforced": r.enforced,
                    "target": r.target,
                }
                for r in result
            ]
        )
    else:
        _print_table(
            ["order", "gpo_id", "gpo_name", "enabled", "enforced", "target"],
            [
                [str(r.order), r.gpo_id, r.gpo_name, str(r.enabled), str(r.enforced), r.target]
                for r in result
            ],
        )


def cmd_dangling(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.dangling_links(estate)
    if args.json:
        _render_json(
            [
                {
                    "som_path": som.path,
                    "som_name": som.name,
                    "gpo_id": link.gpo_id,
                    "order": link.order,
                }
                for som, link in result
            ]
        )
    else:
        _print_table(
            ["som_path", "som_name", "gpo_id", "order"],
            [[som.path, som.name, link.gpo_id, str(link.order)] for som, link in result],
        )


def cmd_enforced(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.enforced_links(estate)
    if args.json:
        _render_json(
            [
                {
                    "som_path": som.path,
                    "som_name": som.name,
                    "gpo_id": link.gpo_id,
                    "order": link.order,
                    "target": link.target,
                }
                for som, link in result
            ]
        )
    else:
        _print_table(
            ["som_path", "som_name", "gpo_id", "order", "target"],
            [
                [som.path, som.name, link.gpo_id, str(link.order), link.target]
                for som, link in result
            ],
        )


def cmd_loopback(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.loopback_gpos(estate)
    if args.json:
        _render_json(
            [
                {
                    "id": g.id,
                    "name": g.name,
                    "side": s.side,
                    "cse": s.cse,
                    "identity": s.identity,
                    "display_value": s.display_value,
                }
                for g, s in result
            ]
        )
    else:
        _print_table(
            ["id", "name", "side", "cse", "identity", "display_value"],
            [[g.id, g.name, s.side, s.cse, s.identity, s.display_value] for g, s in result],
        )


def cmd_wmi(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    if args.json:
        _render_json(
            [
                {"id": g.id, "name": g.name, "wmi_filter": g.wmi_filter}
                for g in queries.wmi_filtered_gpos(estate)
            ]
        )
    else:
        _print_table(
            ["id", "name", "wmi_filter"],
            [[g.id, g.name, g.wmi_filter or ""] for g in queries.wmi_filtered_gpos(estate)],
        )


def cmd_wmi_filters(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    if args.json:
        _render_json([{"name": wf.name, "query": wf.query} for wf in estate.wmi_filters])
    else:
        _print_table(
            ["name", "query"],
            [[wf.name, wf.query] for wf in estate.wmi_filters],
        )


def cmd_topology_check(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.topology_crosscheck(estate)
    if args.json:
        _render_json([{"kind": d.kind, "ou_dn": d.ou_dn, "detail": d.detail} for d in result])
    else:
        if not result:
            print("No discrepancies found.")
        else:
            _print_table(
                ["kind", "ou_dn", "detail"],
                [[d.kind, d.ou_dn, d.detail] for d in result],
            )


def cmd_scope(args: argparse.Namespace) -> int:
    estate = _get_estate(args)
    result = queries.effective_scope(estate, args.gpo)
    if result is None:
        # Error to stderr + nonzero exit so a --json consumer never sees a
        # plain-text "not found" on stdout mistaken for a success payload.
        print(f"GPO not found: {args.gpo}", file=sys.stderr)
        return 1
    if args.json:
        _render_json(
            {
                "gpo_id": result.gpo_id,
                "gpo_name": result.gpo_name,
                "domain": result.domain,
                "computer_enabled": result.computer_enabled,
                "user_enabled": result.user_enabled,
                "links": [
                    {
                        "som_name": lnk.som_name,
                        "som_path": lnk.som_path,
                        "enabled": lnk.link_enabled,
                        "enforced": lnk.enforced,
                    }
                    for lnk in result.links
                ],
                "security_filtering": {
                    "is_filtered": result.security_filtering.is_filtered,
                    "apply_trustees": result.security_filtering.apply_trustees,
                    "has_au_read": result.security_filtering.has_au_read,
                    "has_dc_read": result.security_filtering.has_dc_read,
                },
                "wmi_filter": {
                    "name": result.wmi_filter.name,
                    "query": result.wmi_filter.query,
                    "is_broken": result.wmi_filter.is_broken,
                }
                if result.wmi_filter
                else None,
                "loopback_mode": result.loopback_mode,
                "caveats": result.caveats,
            }
        )
    else:
        print(f"\n  GPO: {result.gpo_name} ({result.gpo_id})")
        print(f"  Domain: {result.domain}")
        print(f"  Computer side: {'enabled' if result.computer_enabled else 'DISABLED'}")
        print(f"  User side: {'enabled' if result.user_enabled else 'DISABLED'}")
        print(f"\n  Links ({len(result.links)}):")
        for lnk in result.links:
            state = "enabled" if lnk.link_enabled else "DISABLED"
            enf = " [ENFORCED]" if lnk.enforced else ""
            print(f"    {lnk.som_name} ({state}){enf}")
        print("\n  Security filtering:")
        sf = result.security_filtering
        if sf.is_filtered:
            trustees = ", ".join(sf.apply_trustees) if sf.apply_trustees else "(none found)"
            print(f"    FILTERED — explicit Apply Group Policy trustees: {trustees}")
            print("    (exclusivity not evaluated; default ACEs and group membership not modeled)")
        else:
            print("    Not filtered (broad application)")
        print(f"    AU Read: {'yes' if sf.has_au_read else 'NO'}")
        print(f"    DC Read: {'yes' if sf.has_dc_read else 'NO'}")
        if result.wmi_filter:
            broken = " [BROKEN]" if result.wmi_filter.is_broken else ""
            print(f"\n  WMI filter: {result.wmi_filter.name}{broken}")
            if result.wmi_filter.query:
                print(f"    {result.wmi_filter.query}")
        if result.loopback_mode:
            print(f"\n  Loopback: {result.loopback_mode.upper()}")
        if result.caveats:
            print("\n  Caveats:")
            for c in result.caveats:
                print(f"    {c}")
        print()
    return 0


def cmd_sites(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    scopes = queries.site_scopes(estate)
    if args.json:
        _render_json(
            [
                {
                    "name": s.name,
                    "dn": s.dn,
                    "links": [
                        {
                            "gpo_id": lnk.gpo_id,
                            "gpo_name": lnk.gpo_name,
                            "enabled": lnk.enabled,
                            "enforced": lnk.enforced,
                            "order": lnk.order,
                        }
                        for lnk in s.links
                    ],
                }
                for s in scopes
            ]
        )
        return
    if not scopes:
        print("No AD sites captured (no sites.json in the export).")
        return
    for s in scopes:
        print(f"\n  Site: {s.name}")
        if not s.links:
            print("    (no GPO links)")
            continue
        for lnk in s.links:
            state = "enabled" if lnk.enabled else "DISABLED"
            enf = " [ENFORCED]" if lnk.enforced else ""
            print(f"    {lnk.gpo_name} ({state}){enf}")
    print(
        "\n  Note: site-linked GPOs apply before domain/OU based on the client's "
        "AD site (IP subnet -> site), which is not resolved here."
    )
