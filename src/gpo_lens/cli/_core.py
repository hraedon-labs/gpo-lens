from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from gpo_lens import __version__
from gpo_lens.cli._danger import cmd_danger
from gpo_lens.cli._delegation import cmd_delegation, cmd_perms, cmd_sddl
from gpo_lens.cli._dependencies import cmd_dependencies
from gpo_lens.cli._diff import (
    cmd_baseline_diff,
    cmd_changelog,
    cmd_diff,
    cmd_diff_settings,
    cmd_golden_diff,
    cmd_snapshots,
)
from gpo_lens.cli._estate import cmd_ingest, cmd_summary
from gpo_lens.cli._events import cmd_events, cmd_events_export
from gpo_lens.cli._export import EXPORT_VIEWS, cmd_export
from gpo_lens.cli._helpers import DEFAULT_DB, _begin_output, _end_output, _set_json_kind
from gpo_lens.cli._helpers import _safe_print as print
from gpo_lens.cli._hygiene import (
    cmd_blocked,
    cmd_broken_refs,
    cmd_cpassword,
    cmd_disabled_populated,
    cmd_doctor,
    cmd_empty,
    cmd_gpp_groups,
    cmd_gpp_tasks,
    cmd_ms16_072,
    cmd_unlinked,
    cmd_version_skew,
)
from gpo_lens.cli._narration import cmd_ask, cmd_explain_setting
from gpo_lens.cli._repl import cmd_repl
from gpo_lens.cli._report import cmd_report
from gpo_lens.cli._resultant import cmd_resultant
from gpo_lens.cli._serve import cmd_serve
from gpo_lens.cli._settings import (
    cmd_admx_coverage,
    cmd_admx_gaps,
    cmd_conflicts,
    cmd_precedence_conflicts,
    cmd_search,
    cmd_settings_at,
    cmd_settings_diff,
    cmd_settings_dump,
    cmd_show,
    cmd_som_conflicts,
    cmd_who_sets,
)
from gpo_lens.cli._topology import (
    cmd_dangling,
    cmd_enforced,
    cmd_loopback,
    cmd_scope,
    cmd_sites,
    cmd_som,
    cmd_topology_check,
    cmd_wmi,
    cmd_wmi_filters,
)
from gpo_lens.cli._trends import cmd_trends


@dataclass
class CliArg:
    name: str
    help: str = ""
    choices: list[str] | None = None
    type: Callable[[str], Any] | None = None
    default: str | int | None = None
    dest: str | None = None
    action: str = "store"


@dataclass
class CliCommand:
    name: str
    func: Callable[..., Any]
    help: str
    args: list[CliArg] = field(default_factory=list)
    src_arg: bool = False
    positional_args: list[CliArg] = field(default_factory=list)
    src_first: bool = False


_COMMANDS: list[CliCommand] = [
    CliCommand(
        name="summary",
        func=cmd_summary,
        help="Estate health overview",
        src_arg=True,
    ),
    CliCommand(
        name="ingest",
        func=cmd_ingest,
        help="",
        positional_args=[CliArg(name="sample_dir", help="Collector export directory or ZIP")],
        args=[
            CliArg(name="--admx-dir", help="Additional PolicyDefinitions directory; repeatable"),
            CliArg(
                name="--json",
                dest="_sub_json",
                action="store_true",
                help="JSON output",
            ),
            CliArg(
                name="--diff-latest",
                action="store_true",
                help="After ingesting, diff against the previous snapshot and print the changelog",
            ),
        ],
    ),
    CliCommand(
        name="unlinked",
        func=cmd_unlinked,
        help="",
        src_arg=True,
    ),
    CliCommand(
        name="empty",
        func=cmd_empty,
        help="",
        src_arg=True,
    ),
    CliCommand(
        name="disabled-populated",
        func=cmd_disabled_populated,
        help="",
        src_arg=True,
    ),
    CliCommand(
        name="who-sets",
        func=cmd_who_sets,
        help="",
        positional_args=[CliArg(name="term")],
        src_arg=True,
    ),
    CliCommand(
        name="conflicts",
        func=cmd_conflicts,
        help="",
        src_arg=True,
    ),
    CliCommand(
        name="blocked",
        func=cmd_blocked,
        help="",
        src_arg=True,
    ),
    CliCommand(
        name="version-skew",
        func=cmd_version_skew,
        help="",
        src_arg=True,
    ),
    CliCommand(
        name="ms16-072",
        func=cmd_ms16_072,
        help="",
        src_arg=True,
    ),
    CliCommand(
        name="cpassword",
        func=cmd_cpassword,
        help="",
        args=[
            CliArg(
                name="--show-secrets",
                action="store_true",
                help="Reveal full cpassword values (default: masked)",
            ),
        ],
        src_arg=True,
    ),
    CliCommand(
        name="search",
        func=cmd_search,
        help="Full-text search",
        positional_args=[CliArg(name="term")],
        args=[
            CliArg(
                name="--scope",
                default="all",
                choices=["all", "settings", "names", "delegation"],
            ),
        ],
        src_arg=True,
    ),
    CliCommand(
        name="show",
        func=cmd_show,
        help="",
        positional_args=[CliArg(name="gpo_id")],
        args=[
            CliArg(name="--format", choices=["text", "json"], default="text"),
        ],
        src_arg=True,
    ),
    CliCommand(
        name="perms",
        func=cmd_perms,
        help="",
        src_arg=True,
    ),
    CliCommand(
        name="delegation",
        func=cmd_delegation,
        help="Delegation deep-dive audit",
        args=[
            CliArg(
                name="--rollup",
                action="store_true",
                help="Show estate-wide trustee → GPO matrix (breadth-sorted)",
            ),
        ],
        src_arg=True,
    ),
    CliCommand(
        name="sddl",
        func=cmd_sddl,
        help="Parse and display SDDL for GPOs",
        src_arg=True,
    ),
    CliCommand(
        name="diff",
        func=cmd_diff,
        help="",
        positional_args=[
            CliArg(name="snapshot_a", type=int),
            CliArg(name="snapshot_b", type=int),
        ],
    ),
    CliCommand(
        name="snapshots",
        func=cmd_snapshots,
        help="",
    ),
    CliCommand(
        name="events",
        func=cmd_events,
        help="Query the append-only event log",
        args=[
            CliArg(name="--since", help="Filter events by timestamp (ISO 8601 prefix)"),
            CliArg(
                name="--type",
                dest="event_type",
                help="Filter events by event_type (substring match)",
            ),
            CliArg(
                name="--limit",
                type=int,
                default=1000,
                help="Max events to return (default: 1000)",
            ),
        ],
    ),
    CliCommand(
        name="events-export",
        func=cmd_events_export,
        help="Export events to NDJSON and/or Splunk HEC",
        args=[
            CliArg(name="--ndjson", help="Path to write NDJSON output"),
            CliArg(name="--since", help="Filter events by timestamp (ISO 8601 prefix)"),
            CliArg(
                name="--sink",
                choices=["hec"],
                help="External sink to send events to",
            ),
        ],
    ),
    CliCommand(
        name="diff-settings",
        func=cmd_diff_settings,
        help="Per-setting delta between two snapshots",
        positional_args=[
            CliArg(name="snapshot_a", type=int),
            CliArg(name="snapshot_b", type=int),
        ],
        args=[
            CliArg(name="--gpo-id", help="Filter to a specific GPO ID"),
            CliArg(name="--side", help="Filter by side (Computer/User)"),
            CliArg(name="--cse", help="Filter by CSE name"),
        ],
    ),
    CliCommand(
        name="changelog",
        func=cmd_changelog,
        help="Version-aware change log between two snapshots",
        positional_args=[
            CliArg(name="snapshot_a", type=int),
            CliArg(name="snapshot_b", type=int),
        ],
        args=[
            CliArg(name="--gpo-id", help="Filter to a specific GPO ID"),
            CliArg(name="--side", help="Filter by side (Computer/User)"),
        ],
    ),
    CliCommand(
        name="som",
        func=cmd_som,
        help="Show effective GPOs at a SOM path",
        positional_args=[CliArg(name="som_path")],
        src_arg=True,
    ),
    CliCommand(
        name="dangling",
        func=cmd_dangling,
        help="SOM links to non-existent GPOs",
        src_arg=True,
    ),
    CliCommand(
        name="enforced",
        func=cmd_enforced,
        help="All enforced (NoOverride) links",
        src_arg=True,
    ),
    CliCommand(
        name="loopback",
        func=cmd_loopback,
        help="GPOs that configure loopback processing",
        src_arg=True,
    ),
    CliCommand(
        name="wmi",
        func=cmd_wmi,
        help="GPOs with WMI filters attached",
        src_arg=True,
    ),
    CliCommand(
        name="wmi-filters",
        func=cmd_wmi_filters,
        help="List WMI filters with query text",
        src_arg=True,
    ),
    CliCommand(
        name="sites",
        func=cmd_sites,
        help="AD sites and their GPO links (lowest precedence; not resolved per-machine)",
        src_arg=True,
    ),
    CliCommand(
        name="topology-check",
        func=cmd_topology_check,
        help="Cross-check ou-tree.json against gp-inheritance.json",
        src_arg=True,
    ),
    CliCommand(
        name="scope",
        func=cmd_scope,
        help="Show effective scoping for a GPO (links, security filtering, WMI, loopback)",
        positional_args=[CliArg(name="gpo", help="GPO name or canonical id")],
        src_arg=True,
    ),
    CliCommand(
        name="admx-gaps",
        func=cmd_admx_gaps,
        help="Flag Registry CSE settings with raw key paths (no ADMX policy name)",
        args=[
            CliArg(name="--admx-dir", help="PolicyDefinitions directory for crosswalk"),
        ],
        src_arg=True,
    ),
    CliCommand(
        name="admx-coverage",
        func=cmd_admx_coverage,
        help="Estate-wide ADMX template inventory and gap detection",
        args=[
            CliArg(name="--admx-dir", help="PolicyDefinitions directory for crosswalk"),
        ],
        src_arg=True,
    ),
    CliCommand(
        name="settings-at",
        func=cmd_settings_at,
        help="Show effective settings at a SOM path",
        positional_args=[CliArg(name="som_path")],
        src_arg=True,
    ),
    CliCommand(
        name="som-conflicts",
        func=cmd_som_conflicts,
        help="Settings that conflict in the SOM chain",
        positional_args=[CliArg(name="som_path")],
        src_arg=True,
    ),
    CliCommand(
        name="precedence-conflicts",
        func=cmd_precedence_conflicts,
        help="All precedence conflicts across the estate",
        src_arg=True,
    ),
    CliCommand(
        name="dependencies",
        func=cmd_dependencies,
        help="Inventory external server/share dependencies without probing reachability",
        src_arg=True,
        args=[
            CliArg(name="--server", default="", help="Filter by server name"),
            CliArg(name="--json", dest="_sub_json", action="store_true"),
        ],
    ),
    CliCommand(
        name="broken-refs",
        func=cmd_broken_refs,
        help="Detect broken references in settings (UNC paths, etc.)",
        src_arg=True,
    ),
    CliCommand(
        name="gpp-tasks",
        func=cmd_gpp_tasks,
        help="Inventory of scheduled tasks deployed by GPO (GPP ScheduledTasks.xml)",
        src_arg=True,
    ),
    CliCommand(
        name="gpp-groups",
        func=cmd_gpp_groups,
        help="Local-group membership changes deployed by GPO (GPP Groups.xml)",
        src_arg=True,
    ),
    CliCommand(
        name="settings-dump",
        func=cmd_settings_dump,
        help="Flat export of all settings (pipe-friendly)",
        args=[
            CliArg(name="--side", help="Filter by side (Computer/User)"),
            CliArg(name="--cse", help="Filter by CSE (substring match)"),
            CliArg(name="--gpo", dest="gpo_name", help="Filter by GPO name (substring match)"),
        ],
        src_arg=True,
    ),
    CliCommand(
        name="settings-diff",
        func=cmd_settings_diff,
        help="Diff two settings-dump JSON exports",
        positional_args=[
            CliArg(name="file_a", help="First settings-dump JSON file"),
            CliArg(name="file_b", help="Second settings-dump JSON file"),
        ],
        args=[
            CliArg(name="--side", help="Filter by side (Computer/User)"),
            CliArg(name="--cse", help="Filter by CSE (substring match)"),
            CliArg(name="--gpo", dest="gpo_id", help="Filter by GPO id (substring match)"),
        ],
    ),
    CliCommand(
        name="baseline-diff",
        func=cmd_baseline_diff,
        help="Diff estate settings against a baseline GPO backup",
        src_arg=True,
        src_first=True,
        positional_args=[
            CliArg(name="baseline_dir", help="Baseline GPO directory or .zip file"),
        ],
        args=[
            CliArg(
                name="--admx-dir",
                help="PolicyDefinitions directory for registry-to-policy crosswalk",
            ),
        ],
    ),
    CliCommand(
        name="golden-diff",
        func=cmd_golden_diff,
        help="Diff live estate against a known-good GPO backup (drift detection)",
        src_arg=True,
        src_first=True,
        positional_args=[
            CliArg(name="golden_dir", help="Golden backup GPO directory or .zip file"),
        ],
        args=[
            CliArg(
                name="--admx-dir",
                help="PolicyDefinitions directory for registry-to-policy crosswalk",
            ),
        ],
    ),
    CliCommand(
        name="doctor",
        func=cmd_doctor,
        help="Run all hygiene checks and produce a prioritized findings report",
        src_arg=True,
        args=[
            CliArg(name="--admx-dir", help="Additional PolicyDefinitions directory; repeatable"),
            CliArg(
                name="--explain",
                action="store_true",
                help="Add an LLM-powered plain-English explanation of findings",
            ),
        ],
    ),
    CliCommand(
        name="report",
        func=cmd_report,
        help="Generate estate documentation report",
        args=[
            CliArg(name="--output", help="Output file path (default: stdout)"),
            CliArg(name="--format", choices=["md", "html"], default="md"),
            CliArg(name="--baseline", help="Baseline JSON file for compliance comparison"),
            CliArg(
                name="--since",
                type=int,
                help="Snapshot ID to diff against (requires --db)",
            ),
            CliArg(
                name="--max-settings",
                type=int,
                default=50,
                help="Max settings per GPO to display (default: 50)",
            ),
            CliArg(
                name="--admx-dir",
                help=(
                    "PolicyDefinitions directory for registry-to-policy crosswalk "
                    "(used with --baseline)"
                ),
            ),
        ],
        src_arg=True,
    ),
    CliCommand(
        name="ask",
        func=cmd_ask,
        help="Ask a natural-language question about the estate",
        positional_args=[
            CliArg(name="question", help="Free-text question about the GPO estate"),
        ],
        args=[
            CliArg(
                name="--no-narrate",
                action="store_true",
                help="Print raw query results as JSON without narration",
            ),
        ],
        src_arg=True,
    ),
    CliCommand(
        name="explain-setting",
        func=cmd_explain_setting,
        help="Explain what a registry setting / GPO identity does",
        positional_args=[
            CliArg(
                name="identity",
                help="Registry path or setting identity (optionally 'key:value')",
            ),
        ],
        args=[
            CliArg(name="--admx-dir", help="PolicyDefinitions directory for ADMX crosswalk"),
            CliArg(
                name="--side",
                choices=["Computer", "User"],
                help="Setting side for template class matching",
            ),
        ],
    ),
    CliCommand(
        name="repl",
        func=cmd_repl,
        help="Interactive Python REPL with the estate loaded",
        src_arg=True,
    ),
    CliCommand(
        name="danger",
        func=cmd_danger,
        help="Scan for dangerous GPO configurations (curated, cited checks)",
        args=[
            CliArg(name="--json", dest="_sub_json", action="store_true", help="JSON output"),
            CliArg(
                name="--admx-dir",
                help="PolicyDefinitions directory for policy-name-keyed rules",
            ),
        ],
        src_arg=True,
    ),
    CliCommand(
        name="serve",
        func=cmd_serve,
        help="Launch the web UI",
        args=[
            CliArg(name="--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)"),
            CliArg(name="--port", type=int, default=8000, help="Bind port (default: 8000)"),
            CliArg(name="--open", action="store_true", help="Open browser on start"),
            CliArg(
                name="--root-path",
                default="",
                help="ASGI root_path for reverse-proxy mounting",
            ),
            CliArg(
                name="--admx-dir",
                help="PolicyDefinitions directory for registry-to-policy crosswalk",
            ),
        ],
    ),
    CliCommand(
        name="resultant",
        func=cmd_resultant,
        help="Principal resultant (RSoP) — effective policy for a principal",
        positional_args=[
            CliArg(
                name="principal_sid",
                help="SID of the principal (user or computer) to compute resultant for",
            ),
        ],
        args=[
            CliArg(
                name="--computer-sid",
                default=None,
                help="Computer SID (for user+computer pair)",
            ),
            CliArg(
                name="--dn",
                default=None,
                help="Distinguished name of the principal (for SOM chain)",
            ),
            CliArg(
                name="--computer-dn",
                default=None,
                help="Computer DN (for user+computer SOM chain)",
            ),
            CliArg(name="--json", dest="_sub_json", action="store_true", help="JSON output"),
        ],
        src_arg=True,
    ),
    CliCommand(
        name="trends",
        func=cmd_trends,
        help="Posture-over-time from snapshot history",
        args=[
            CliArg(name="--json", dest="_sub_json", action="store_true", help="JSON output"),
            CliArg(
                name="--changes-only",
                action="store_true",
                help="Only show snapshots where key metrics changed",
            ),
        ],
    ),
]


_COMMANDS.append(
    CliCommand(
        name="export",
        func=cmd_export,
        help="Deterministic redacted Markdown/CSV from a stored view",
        positional_args=[CliArg(name="view", choices=EXPORT_VIEWS)],
        args=[
            CliArg(name="--format", choices=["md", "csv"], default="md"),
            CliArg(name="--gpo-id"),
            CliArg(name="--compare", default=""),
            CliArg(name="--snapshot", type=int),
            CliArg(name="--snapshot-a", type=int),
            CliArg(name="--snapshot-b", type=int),
            CliArg(name="--occurrence-id", type=int),
            CliArg(name="--identity"),
            CliArg(name="--side", default=""),
            CliArg(name="--cse", default=""),
            CliArg(name="--q", default=""),
            CliArg(name="--category", default=""),
            CliArg(name="--severity", default=""),
            CliArg(name="--gpo-name", default=""),
            CliArg(name="--lifecycle", default="new_or_regressed"),
            CliArg(name="--triage", default="open"),
            CliArg(name="--page", type=int, default=1),
            CliArg(name="--per-page", type=int, default=50),
            CliArg(
                name="--as-of", help="Explicit ISO timestamp for time-sensitive briefing/risk facts"
            ),
            CliArg(name="--admx-dir"),
            CliArg(name="--comparator"),
            CliArg(name="--file-a"),
            CliArg(name="--file-b"),
        ],
    )
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gpo-lens")
    parser.add_argument("--version", action="version", version=f"gpo-lens {__version__}")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    parser.add_argument("--json", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    def _add_src(p: argparse.ArgumentParser) -> None:
        p.add_argument("src", nargs="?", help="Sample directory (omit to use --db)")

    for cmd in _COMMANDS:
        p = sub.add_parser(cmd.name, help=cmd.help)
        if cmd.src_arg and cmd.src_first:
            _add_src(p)
        for arg in cmd.positional_args:
            pos_kwargs: dict[str, Any] = {"help": arg.help}
            if arg.choices:
                pos_kwargs["choices"] = arg.choices
            if arg.type:
                pos_kwargs["type"] = arg.type
            p.add_argument(arg.name, **pos_kwargs)
        if cmd.src_arg and not cmd.src_first:
            _add_src(p)
        for arg in cmd.args:
            kwargs: dict[str, Any] = {"help": arg.help}
            if arg.choices:
                kwargs["choices"] = arg.choices
            if arg.type:
                kwargs["type"] = arg.type
            if arg.default is not None:
                kwargs["default"] = arg.default
            if arg.dest:
                kwargs["dest"] = arg.dest
            if arg.action != "store":
                kwargs["action"] = arg.action
                kwargs.pop("type", None)
                kwargs.pop("default", None)
            if arg.name == "--admx-dir":
                kwargs["action"] = "append"
            p.add_argument(arg.name, **kwargs)
        p.set_defaults(func=cmd.func)

    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    _set_json_kind(getattr(args, "command", None))
    args.json = bool(args.json) or bool(getattr(args, "_sub_json", False))
    output_token = None
    try:
        output_token = _begin_output(args)
        return args.func(args) or 0
    except SystemExit:
        raise
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        if output_token is not None:
            _end_output(output_token)


if __name__ == "__main__":
    sys.exit(main())
