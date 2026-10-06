"""CLI subcommand for principal resultant (Plan 021)."""

from __future__ import annotations

import argparse
import sys

from gpo_lens.authz import SID_RE
from gpo_lens.cli._helpers import _get_estate, _render_json
from gpo_lens.cli._helpers import _safe_print as print


def cmd_resultant(args: argparse.Namespace) -> int:
    from gpo_lens.merge import principal_resultant

    sid = args.principal_sid.strip()
    if not SID_RE.match(sid):
        print(f"Invalid SID format: {args.principal_sid}", file=sys.stderr)
        return 1

    estate = _get_estate(args)
    result = principal_resultant(
        estate,
        sid,
        computer_sid=args.computer_sid,
        dn=args.dn,
        computer_dn=args.computer_dn,
    )
    if result is None:
        print(f"Principal not found: {args.principal_sid}", file=sys.stderr)
        return 1
    if args.json:
        _render_json(
            {
                "principal_sid": result.principal_sid,
                "principal_name": result.principal_name,
                "computer_sid": result.computer_sid,
                "settings": [
                    {
                        "cse": s.cse,
                        "side": s.side,
                        "identity": s.identity,
                        "display_name": s.display_name,
                        "winning_value": s.winning_value,
                        "winning_gpo_id": s.winning_gpo_id,
                        "winning_gpo_name": s.winning_gpo_name,
                        "merge_mode": s.merge_mode.value,
                        "overridden_by": [{"gpo_name": n, "value": v} for n, v in s.overridden_by],
                        "approximate": s.approximate,
                        "conditional": s.conditional,
                    }
                    for s in result.settings
                ],
                "excluded": [
                    {
                        "gpo_id": e.gpo_id,
                        "gpo_name": e.gpo_name,
                        "kind": e.kind,
                        "reason": e.reason,
                        "side": e.side,
                    }
                    for e in result.excluded
                ],
                "excluded_settings": [
                    {
                        "cse": es.cse,
                        "side": es.side,
                        "identity": es.identity,
                        "kind": es.kind,
                        "gpo_name": es.gpo_name,
                    }
                    for es in result.excluded_settings
                ],
                "conditional_dangers": [
                    {
                        "gpo_id": cd.gpo_id,
                        "gpo_name": cd.gpo_name,
                        "reason": cd.reason,
                        "finding_count": cd.finding_count,
                    }
                    for cd in result.conditional_dangers
                ],
                "token_caveats": result.token_caveats,
                "caveat_summary": result.caveat_summary,
                "caveat_mechanisms": result.caveat_mechanisms,
            }
        )
    else:
        print(f"\n  Principal: {result.principal_name} ({result.principal_sid})")
        if result.computer_sid:
            print(f"  Computer: {result.computer_sid}")
        print(f"\n  {result.caveat_summary}")
        if result.caveat_mechanisms:
            print("\n  Non-simulated mechanisms:")
            for m in result.caveat_mechanisms:
                print(f"    - {m}")
        print(f"\n  Effective settings ({len(result.settings)}):")
        for s in result.settings:
            approx = " [APPROXIMATE]" if s.approximate else ""
            print(f"    {s.cse} / {s.side} / {s.identity}")
            print(f"      = {s.winning_value} (from {s.winning_gpo_name}){approx}")
        if result.excluded:
            print(f"\n  Excluded GPOs ({len(result.excluded)}):")
            for e in result.excluded:
                side_tag = f" [{e.side}]" if e.side else ""
                print(f"    {e.gpo_name}{side_tag}: {e.reason}")
        if result.excluded_settings:
            print(f"\n  Excluded settings ({len(result.excluded_settings)}):")
            for es in result.excluded_settings:
                print(f"    {es.cse}/{es.identity} ({es.gpo_name}): {es.kind}")
        if result.conditional_dangers:
            print(f"\n  Conditional dangers ({len(result.conditional_dangers)}):")
            for cd in result.conditional_dangers:
                print(f"    {cd.gpo_name}: {cd.reason} ({cd.finding_count} finding(s))")
        if result.token_caveats:
            print("\n  Token caveats:")
            for c in result.token_caveats:
                print(f"    {c}")
        print()
    return 0
