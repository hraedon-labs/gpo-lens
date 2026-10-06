"""CLI subcommands for GPO hygiene checks (doctor, cpassword, version-skew, etc.)."""

from __future__ import annotations

import argparse
import sys

from gpo_lens import queries
from gpo_lens.cli._helpers import _get_estate, _print_table, _render_json
from gpo_lens.cli._helpers import _safe_print as print
from gpo_lens.detection import local_group_mods, mask_cpassword, scheduled_tasks


def cmd_unlinked(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.unlinked_gpos(estate)
    if args.json:
        _render_json([{"id": g.id, "name": g.name} for g in result])
    else:
        _print_table(["id", "name"], [[g.id, g.name] for g in result])


def cmd_empty(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.empty_gpos(estate)
    if args.json:
        _render_json([{"id": g.id, "name": g.name} for g in result])
    else:
        _print_table(["id", "name"], [[g.id, g.name] for g in result])


def cmd_disabled_populated(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.disabled_but_populated(estate)
    if args.json:
        _render_json([{"id": g.id, "name": g.name, "side": side} for g, side in result])
    else:
        _print_table(
            ["id", "name", "side"],
            [[g.id, g.name, side] for g, side in result],
        )


def cmd_blocked(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.blocked_extensions(estate)
    if args.json:
        _render_json(
            [{"id": g.id, "name": g.name, "side": side, "cse": cse} for g, side, cse in result]
        )
    else:
        _print_table(
            ["id", "name", "side", "cse"],
            [[g.id, g.name, side, cse] for g, side, cse in result],
        )


def cmd_version_skew(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.version_skew(estate)
    if args.json:
        _render_json([{"id": g.id, "name": g.name, "side": side} for g, side in result])
    else:
        _print_table(
            ["id", "name", "side"],
            [[g.id, g.name, side] for g, side in result],
        )


def cmd_ms16_072(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.ms16_072_vulnerable(estate)
    if args.json:
        _render_json([{"id": g.id, "name": g.name} for g in result])
    else:
        _print_table(["id", "name"], [[g.id, g.name] for g in result])


def cmd_cpassword(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.cpassword_scan(estate)
    show = getattr(args, "show_secrets", False)
    if args.json:
        _render_json(
            [
                {
                    "gpo_id": h.gpo_id,
                    "gpo_name": h.gpo_name,
                    "file": h.file,
                    "tag": h.tag,
                    "cpassword": h.cpassword if show else mask_cpassword(h.cpassword),
                }
                for h in result
            ]
        )
    else:
        _print_table(
            ["gpo_id", "file", "tag", "cpassword"],
            [
                [h.gpo_id, h.file, h.tag, h.cpassword if show else mask_cpassword(h.cpassword)]
                for h in result
            ],
        )


def cmd_broken_refs(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.broken_refs(estate)
    if args.json:
        _render_json(
            [
                {
                    "gpo_id": r.gpo_id,
                    "gpo_name": r.gpo_name,
                    "ref_type": r.ref_type,
                    "ref_value": r.ref_value,
                    "detail": r.detail,
                }
                for r in result
            ]
        )
    else:
        _print_table(
            ["gpo_id", "gpo_name", "ref_type", "ref_value", "detail"],
            [[r.gpo_id, r.gpo_name, r.ref_type, r.ref_value, r.detail] for r in result],
        )


def cmd_gpp_tasks(args: argparse.Namespace) -> None:
    """Structured inventory of scheduled tasks deployed by GPO."""
    estate = _get_estate(args)
    result = scheduled_tasks(estate)
    # SYSVOL task arguments may be absent from the report's Setting subtrees.
    # Carry the structured command context into text and copied output fields.
    from gpo_lens.cli._helpers import _add_secret_source

    _add_secret_source(result)
    if args.json:
        _render_json(
            [
                {
                    "gpo_id": t.gpo_id,
                    "gpo_name": t.gpo_name,
                    "side": t.side,
                    "file": t.file,
                    "kind": t.kind,
                    "name": t.name,
                    "action": t.action,
                    "command": t.command,
                    "arguments": t.arguments,
                    "run_as": t.run_as,
                }
                for t in result
            ]
        )
    else:
        _print_table(
            ["gpo", "side", "kind", "name", "action", "command", "run_as"],
            [[t.gpo_name, t.side, t.kind, t.name, t.action, t.command, t.run_as] for t in result],
        )


def cmd_gpp_groups(args: argparse.Namespace) -> None:
    """Structured inventory of local-group membership changes by GPO."""
    estate = _get_estate(args)
    result = local_group_mods(estate)
    if args.json:
        _render_json(
            [
                {
                    "gpo_id": m.gpo_id,
                    "gpo_name": m.gpo_name,
                    "side": m.side,
                    "file": m.file,
                    "group_name": m.group_name,
                    "group_sid": m.group_sid,
                    "members_added": list(m.members_added),
                    "members_removed": list(m.members_removed),
                }
                for m in result
            ]
        )
    else:
        _print_table(
            ["gpo", "side", "group", "sid", "+added", "-removed"],
            [
                [
                    m.gpo_name,
                    m.side,
                    m.group_name,
                    m.group_sid,
                    "; ".join(m.members_added),
                    "; ".join(m.members_removed),
                ]
                for m in result
            ],
        )


def _doctor_findings_as_dicts(
    findings: list[queries.DoctorFinding],
) -> list[dict[str, str]]:
    return [
        {
            "severity": f.severity,
            "category": f.category,
            "gpo_id": f.gpo_id,
            "gpo_name": f.gpo_name,
            "summary": f.summary,
            "detail": f.detail,
        }
        for f in findings
    ]


def _print_doctor_text(findings: list[queries.DoctorFinding]) -> None:
    if not findings:
        print("No issues detected. Estate looks healthy.")
        return
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    print("Estate Doctor — Findings")
    print("=" * 60)
    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in sev_counts:
            parts.append(f"{sev}: {sev_counts[sev]}")
    print("  " + " | ".join(parts))
    print()

    current_sev = None
    for f in findings:
        if f.severity != current_sev:
            current_sev = f.severity
            print(f"--- {current_sev.upper()} ---")
        gpo_part = f" [{f.gpo_name or f.gpo_id}]" if f.gpo_id else ""
        print(f"  {f.category}{gpo_part}: {f.summary}")
        if f.detail:
            print(f"    {f.detail}")


def cmd_doctor(args: argparse.Namespace) -> None:
    from gpo_lens.narration import NarrationUnavailable, explain_findings

    estate = _get_estate(args)
    findings = queries.estate_doctor(estate)
    findings_dicts = _doctor_findings_as_dicts(findings)
    explain = getattr(args, "explain", False)

    narration_text: str | None = None
    if explain:
        try:
            narration_text = explain_findings(findings_dicts)
        except NarrationUnavailable:
            narration_text = None
        except Exception as exc:
            print(f"Warning: narration failed: {exc}", file=sys.stderr)
            narration_text = None

    if args.json:
        output: dict[str, object] = {"findings": findings_dicts}
        if explain:
            output["narration"] = narration_text
        _render_json(output)
    else:
        if explain and narration_text is not None:
            print(narration_text)
            print()
        _print_doctor_text(findings)
        if explain and narration_text is None:
            print()
            print("Set GPO_LENS_API_KEY to enable AI-powered explanations.")
