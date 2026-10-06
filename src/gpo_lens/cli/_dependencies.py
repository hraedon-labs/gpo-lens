"""Read-only external dependency inventory."""

import argparse

from gpo_lens.cli._helpers import _get_estate, _print_table, _render_json
from gpo_lens.dependencies import external_dependencies


def cmd_dependencies(args: argparse.Namespace) -> None:
    groups = external_dependencies(_get_estate(args), server=args.server)
    if args.json:
        _render_json(groups)
        return
    _print_table(
        ["server", "share", "type", "gpo_id", "gpo_name", "target"],
        [
            [g.server, r.share, r.dependency_type, r.gpo_id, r.gpo_name, r.target]
            for g in groups
            for r in g.dependencies
        ],
    )
    _print_table(
        ["server", "dependencies", "GPOs"],
        [[g.server, str(g.dependency_count), str(g.gpo_count)] for g in groups],
    )
