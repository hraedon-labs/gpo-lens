"""CLI subcommands for delegation and permissions audit."""

from __future__ import annotations

import argparse

from gpo_lens import queries
from gpo_lens.cli._helpers import _get_estate, _print_table, _render_json
from gpo_lens.cli._helpers import _safe_print as print


def cmd_perms(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.permissions_audit(estate)
    if args.json:
        _render_json([{"id": g.id, "name": g.name, "issue": desc} for g, desc in result])
    else:
        _print_table(
            ["id", "name", "issue"],
            [[g.id, g.name, desc] for g, desc in result],
        )


def cmd_delegation(args: argparse.Namespace) -> None:
    estate = _get_estate(args)

    if getattr(args, "rollup", False):
        rollup = queries.delegation_rollup(estate)
        if args.json:
            _render_json(
                [
                    {
                        "trustee": e.trustee,
                        "trustee_sid": e.trustee_sid,
                        "resolved_name": e.resolved_name,
                        "is_resolved": e.is_resolved,
                        "is_unknown_sid": e.is_unknown_sid,
                        "is_default_writer": e.is_default_writer,
                        "gpo_count": e.gpo_count,
                        "gpo_names": list(e.gpo_names),
                        "permissions": list(e.permissions),
                    }
                    for e in rollup
                ]
            )
        else:
            if not rollup:
                print("No non-Read delegation entries found.")
                return
            print("Delegation Rollup (Trustee → Editable GPOs)")
            print("=" * 60)
            for e in rollup:
                unknown = " [UNKNOWN SID]" if e.is_unknown_sid else ""
                default = " [default writer]" if e.is_default_writer else ""
                print(f"\n  {e.resolved_name}{unknown}{default}")
                print(f"    SID: {e.trustee_sid or 'N/A'}")
                print(f"    GPOs ({e.gpo_count}): {', '.join(e.gpo_names[:10])}")
                if len(e.gpo_names) > 10:
                    print(f"    ... and {len(e.gpo_names) - 10} more")
                print(f"    Permissions: {', '.join(e.permissions)}")
            unknown_count = sum(1 for e in rollup if e.is_unknown_sid)
            if unknown_count:
                print(f"\n  {unknown_count} unknown SID(s) detected.")
        return

    audit = queries.delegation_deep_dive(estate)
    if args.json:
        _render_json(
            {
                "privilege_rollup": {
                    trustee: sorted(set(gpo_names))
                    for trustee, gpo_names in audit.privilege_rollup.items()
                },
                "orphaned_sids": [
                    {"gpo_id": g.id, "gpo_name": g.name, "sid": sid}
                    for g, sid in audit.orphaned_sids
                ],
                "broad_writers": [
                    {
                        "gpo_id": g.id,
                        "gpo_name": g.name,
                        "trustee": d.trustee,
                        "permission": d.permission,
                    }
                    for g, d in audit.broad_writers
                ],
                "deny_aces": [
                    {
                        "gpo_id": d.gpo_id,
                        "gpo_name": d.gpo_name,
                        "trustee_sid": d.trustee_sid,
                        "resolved_name": d.trustee_name,
                        "rights": d.rights,
                        "flags": d.flags,
                    }
                    for d in audit.deny_aces
                ],
                "excessive_writers": [
                    {
                        "trustee_sid": w.trustee_sid,
                        "resolved_name": w.trustee_name,
                        "gpo_count": w.gpo_count,
                        "gpo_names": w.gpo_names,
                        "rights": w.rights,
                    }
                    for w in audit.excessive_writers
                ],
            }
        )
    else:
        print("Delegation Deep-Dive")
        print("=" * 60)
        if audit.deny_aces:
            print("\n--- Deny ACEs ---")
            for d in audit.deny_aces:
                flags_part = f" [{d.flags}]" if d.flags else ""
                resolved = d.trustee_name and d.trustee_name != d.trustee_sid
                name_part = f"{d.trustee_name} " if resolved else ""
                print(f"  {d.gpo_name}: {name_part}{d.trustee_sid} ({d.rights}){flags_part}")
        if audit.excessive_writers:
            print("\n--- Excessive Write Access ---")
            for w in audit.excessive_writers:
                resolved = w.trustee_name and w.trustee_name != w.trustee_sid
                name_part = f"{w.trustee_name} " if resolved else ""
                print(f"  {name_part}{w.trustee_sid}: {w.gpo_count} GPOs ({', '.join(w.rights)})")
                for name in w.gpo_names[:5]:
                    print(f"    - {name}")
                if len(w.gpo_names) > 5:
                    print(f"    ... and {len(w.gpo_names) - 5} more")
        if audit.orphaned_sids:
            print("\n--- Orphaned SIDs ---")
            for g, sid in audit.orphaned_sids:
                print(f"  {g.name}: {sid}")
        if audit.broad_writers:
            print("\n--- Non-Default Editors with Write Rights ---")
            for g, de in audit.broad_writers:
                print(f"  {g.name}: {de.trustee} ({de.permission})")
        if audit.privilege_rollup:
            print("\n--- Privilege Rollup ---")
            for trustee, gpo_names in sorted(audit.privilege_rollup.items()):
                print(f"  {trustee}: {', '.join(sorted(set(gpo_names)))}")
        if not (
            audit.orphaned_sids
            or audit.broad_writers
            or audit.privilege_rollup
            or audit.deny_aces
            or audit.excessive_writers
        ):
            print("No delegation issues found.")


def cmd_sddl(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    if args.json:
        json_results: list[dict[str, object]] = []
        for g in estate.gpos:
            if not g.sddl:
                continue
            acl = queries.parse_sddl(g.sddl)
            json_results.append(
                {
                    "gpo_id": g.id,
                    "gpo_name": g.name,
                    "owner_sid": acl.owner_sid or "",
                    "group_sid": acl.group_sid or "",
                    "dacl": [
                        {
                            "ace_type": a.ace_type,
                            "flags": a.flags,
                            "rights": a.rights,
                            "object_guid": a.object_guid,
                            "inherit_object_guid": a.inherit_object_guid,
                            "trustee_sid": a.trustee_sid,
                        }
                        for a in acl.dacl
                    ],
                    "sacl": [
                        {
                            "ace_type": a.ace_type,
                            "flags": a.flags,
                            "rights": a.rights,
                            "object_guid": a.object_guid,
                            "inherit_object_guid": a.inherit_object_guid,
                            "trustee_sid": a.trustee_sid,
                        }
                        for a in acl.sacl
                    ],
                }
            )
        _render_json(json_results)
    else:
        found = False
        for g in estate.gpos:
            if not g.sddl:
                continue
            found = True
            acl = queries.parse_sddl(g.sddl)
            print(f"\n{g.name} ({g.id})")
            print(f"  Owner: {acl.owner_sid or 'N/A'}")
            for a in acl.dacl:
                flags = f" [{a.flags}]" if a.flags else ""
                print(f"  DACL {a.ace_type.upper()}: {a.trustee_sid} ({a.rights}){flags}")
            for a in acl.sacl:
                flags = f" [{a.flags}]" if a.flags else ""
                print(f"  SACL {a.ace_type.upper()}: {a.trustee_sid} ({a.rights}){flags}")
        if not found:
            print("No GPOs with SDDL data found.")
