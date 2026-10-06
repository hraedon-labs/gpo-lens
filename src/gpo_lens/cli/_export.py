"""Read-only deterministic exports; existing --json commands are unchanged."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path
from typing import Any, cast

from gpo_lens import ingest, queries, store, topology
from gpo_lens.briefing import briefing_lines, build_briefing
from gpo_lens.cli._helpers import _get_admx
from gpo_lens.exports import (
    ExportDocument,
    ExportSection,
    compare_ledgers,
    export_metadata,
    filter_ledger,
    ledger_payload,
    occurrence_run_ids,
    render_export,
    setting_payload,
    snapshot_secrets,
)
from gpo_lens.findings import (
    accepted_risk_register,
    finding_history,
    finding_inbox,
    finding_inbox_count,
    finding_observation_history,
    load_triage_status_map,
)
from gpo_lens.model import Estate
from gpo_lens.normalize import canonical_guid, load_json, parse_dt
from gpo_lens.safe_output import safe_data, secret_values
from gpo_lens.snapshot_diff import snapshot_changelog, snapshot_diff, snapshot_settings_diff

EXPORT_VIEWS = [
    "dossier",
    "ledger",
    "findings",
    "occurrence",
    "accepted-risks",
    "briefing",
    "setting",
    "diff",
    "diff-settings",
    "changelog",
    "baseline-diff",
    "golden-diff",
    "settings-dump",
    "settings-diff",
    "who-sets",
]


def _required(value: object, flag: str) -> None:
    if value is None or value == "":
        raise ValueError(f"{flag} is required for this export")


def cmd_export(args: argparse.Namespace) -> None:
    if args.json:
        raise ValueError("export supports --format md|csv; use the existing command for --json")
    path = Path(args.db).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Database not found: {path}")
    conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        conn.execute("BEGIN")  # pin all queries/provenance to one read transaction
        snapshot = args.snapshot
        if snapshot is None:
            row = conn.execute("SELECT MAX(id) FROM snapshot").fetchone()
            snapshot = row[0]
        snapshots = [snapshot] if snapshot is not None else []
        runs = None
        admx = _get_admx(args)
        comparator: object = None
        comparator_secrets: tuple[str, ...] = ()
        args.per_page = max(1, min(args.per_page, 10_000))
        filters: dict[str, object] = {}
        sections: tuple[ExportSection, ...]
        view = args.view
        as_of = parse_dt(args.as_of)
        if args.as_of and (as_of is None or as_of.tzinfo is None or as_of.utcoffset() is None):
            raise ValueError("--as-of must be an ISO timestamp with a UTC offset")
        if view in {"dossier", "ledger", "setting", "settings-dump", "who-sets"}:
            estate = store.load_estate(conn, snapshot_id=snapshot)
            if view in {"dossier", "ledger"}:
                _required(args.gpo_id, "--gpo-id")
                gpo_id = canonical_guid(args.gpo_id)
                gpo = estate.gpo_by_id(gpo_id)
                if gpo is None:
                    raise ValueError("GPO not found")
                ledger = filter_ledger(
                    ledger_payload(estate, gpo_id, admx), q=args.q, side=args.side, cse=args.cse
                )
                sections = (ExportSection("settings_ledger", ledger),)
                if view == "dossier":
                    projected = safe_data(gpo)
                    scope = topology.effective_scope(estate, gpo_id)
                    sections = (
                        ExportSection(
                            "dossier",
                            (
                                {
                                    k: v
                                    for k, v in projected.items()
                                    if k not in {"settings", "links", "delegation", "sysvol_path"}
                                },
                            ),
                        ),
                        ExportSection("links", projected["links"]),
                        ExportSection("delegation", projected["delegation"]),
                        *sections,
                        ExportSection(
                            "scope",
                            (
                                {
                                    "scope": scope,
                                    "security_filtering": topology.security_filtering_detail(
                                        gpo, estate
                                    ),
                                },
                            ),
                        ),
                    )
                    if args.compare:
                        compare_id = canonical_guid(args.compare)
                        if estate.gpo_by_id(compare_id) is None:
                            raise ValueError("Comparison GPO not found")
                        diff = compare_ledgers(
                            queries.settings_ledger(estate, gpo_id, admx=admx),
                            queries.settings_ledger(estate, compare_id, admx=admx),
                        )
                        sections += (
                            ExportSection(
                                "gpo_comparison",
                                safe_data({"rows": diff, "source": estate.gpos})["rows"],
                            ),
                        )
                filters = {
                    "gpo_id": gpo_id,
                    "compare": args.compare,
                    "q": args.q,
                    "side": args.side,
                    "cse": args.cse,
                }
            elif view == "setting":
                _required(args.identity, "--identity")
                sections = (
                    ExportSection(
                        "settings",
                        setting_payload(
                            estate, args.identity, cse=args.cse, side=args.side, admx=admx
                        ),
                    ),
                )
                filters = {"identity": args.identity, "side": args.side, "cse": args.cse}
            elif view == "settings-dump":
                rows = queries.settings_dump(
                    estate,
                    side=args.side or None,
                    cse=args.cse or None,
                    gpo_name=args.gpo_name or None,
                )
                sections = (
                    ExportSection(
                        "settings", safe_data({"rows": rows, "source": estate.gpos})["rows"]
                    ),
                )
                filters = {"side": args.side, "cse": args.cse, "gpo_name": args.gpo_name}
            else:
                _required(args.q, "--q")
                sections = (ExportSection("settings", queries.who_sets(estate, args.q)),)
                filters = {"q": args.q}
        elif view == "findings":
            status_map = load_triage_status_map(conn)
            severities = [s.strip() for s in args.severity.split(",") if s.strip()]
            query_filters: dict[str, Any] = {
                "lifecycle_state": None if args.lifecycle == "all" else args.lifecycle,
                "triage_status": None if args.triage == "all" else args.triage,
                "category_prefix": args.category or None,
                "severities": severities or None,
                "search": args.q[:200] or None,
                "status_map": status_map,
            }
            count = finding_inbox_count(conn, **query_filters)
            page = min(max(1, args.page), max(1, (count + args.per_page - 1) // args.per_page))
            views = finding_inbox(
                conn, limit=args.per_page, offset=(page - 1) * args.per_page, **query_filters
            )
            sections = (
                ExportSection("findings", views),
                ExportSection(
                    "evidence_refs",
                    (
                        {
                            "occurrence_id": v.occurrence_id,
                            "run_id": v.last_seen_run_id,
                            "gpo_id": v.gpo_id,
                            "source": "finding_observation",
                            "redaction": "raw source [REDACTED]",
                        }
                        for v in views
                    ),
                ),
                ExportSection(
                    "triage_state",
                    (
                        {"occurrence_id": v.occurrence_id, "state": status_map.get(v.occurrence_id)}
                        for v in views
                    ),
                ),
            )
            runs = occurrence_run_ids(conn, (v.occurrence_id for v in views))
            filters = {k: v for k, v in query_filters.items() if k != "status_map"}
            filters.update({"page": page, "per_page": args.per_page, "total": count})
        elif view == "occurrence":
            _required(args.occurrence_id, "--occurrence-id")
            history = finding_history(conn, args.occurrence_id)
            observations = finding_observation_history(conn, args.occurrence_id)
            snapshots = sorted({o["snapshot_id"] for o in observations})
            runs = sorted({o["run_id"] for o in observations})
            sections = (
                ExportSection("occurrence", (history.occurrence,)),
                ExportSection("observations", observations),
                ExportSection("triage_events", history.triage_events),
            )
            filters = {"occurrence_id": args.occurrence_id}
        elif view == "accepted-risks":
            risks = accepted_risk_register(conn, as_of=as_of)
            risks = [
                r
                for r in risks
                if (not args.category or r.category == args.category)
                and (not args.severity or r.severity == args.severity)
                and (not args.q or args.q.lower() in (r.summary + " " + r.category).lower())
            ]
            runs = occurrence_run_ids(conn, (r.occurrence_id for r in risks))
            page = min(max(1, args.page), max(1, (len(risks) + args.per_page - 1) // args.per_page))
            sections = (
                ExportSection(
                    "accepted_risks", risks[(page - 1) * args.per_page : page * args.per_page]
                ),
            )
            filters = {
                "as_of": args.as_of or "current triage state",
                "category": args.category,
                "severity": args.severity,
                "q": args.q,
                "page": page,
                "per_page": args.per_page,
            }
        elif view == "briefing":
            briefing = build_briefing(conn, as_of_snapshot=snapshot, now=as_of)
            sections = (
                ExportSection("briefing", (briefing,) if briefing else ()),
                ExportSection("sentences", briefing_lines(briefing) if briefing else ()),
            )
            filters = {"snapshot": snapshot, "as_of": args.as_of or "current triage state"}
        elif view in {"diff", "diff-settings", "changelog"}:
            _required(args.snapshot_a, "--snapshot-a")
            _required(args.snapshot_b, "--snapshot-b")
            snapshots = sorted({args.snapshot_a, args.snapshot_b})
            if view == "diff":
                result: Any = [snapshot_diff(conn, args.snapshot_a, args.snapshot_b)]
            elif view == "diff-settings":
                result = snapshot_settings_diff(
                    conn,
                    args.snapshot_a,
                    args.snapshot_b,
                    gpo_id=args.gpo_id,
                    side=args.side or None,
                    cse=args.cse or None,
                )
            else:
                result = snapshot_changelog(conn, args.snapshot_a, args.snapshot_b)
                if args.gpo_id:
                    result = [r for r in result if r.gpo_id == args.gpo_id]
                if args.side:
                    result = [r for r in result if r.side and r.side.lower() == args.side.lower()]
            sections = (ExportSection(view, result),)
            filters = {
                "snapshot_a": args.snapshot_a,
                "snapshot_b": args.snapshot_b,
                "gpo_id": args.gpo_id,
                "side": args.side,
                "cse": args.cse,
            }
        elif view == "settings-diff":
            _required(args.file_a, "--file-a")
            _required(args.file_b, "--file-b")
            comparator = {"file_a": load_json(args.file_a), "file_b": load_json(args.file_b)}
            comparator_secrets = secret_values(comparator)
            snapshots = []
            runs = []
            result = queries.settings_diff(
                args.file_a,
                args.file_b,
                side=args.side or None,
                cse=args.cse or None,
                gpo_id=args.gpo_id,
            )
            sections = (ExportSection("settings_diff", result),)
            filters = {
                "side": args.side,
                "cse": args.cse,
                "gpo_id": args.gpo_id,
                "skipped": result.skipped_count,
                "comparison": "two-file settings diff; no persisted snapshot/evaluation run",
            }
        else:
            _required(args.comparator, "--comparator")
            estate = store.load_estate(conn, snapshot_id=snapshot)
            path = Path(args.comparator)
            comparator_estate = (
                Estate(gpos=ingest.load_baseline_from_zip(path))
                if path.suffix.lower() == ".zip"
                else ingest.load_estate(path)
            )
            comparator_secrets = secret_values(comparator_estate)
            if view == "baseline-diff":
                comparator = queries.load_baseline_from_estate(comparator_estate)
                result = queries.baseline_diff(estate, comparator, admx)
            else:
                comparator = comparator_estate
                result = queries.golden_diff(estate, comparator_estate, admx)
            sections = (ExportSection("comparison", result),)
            filters = {"comparison": view, "evaluation": "ad hoc; no persisted comparison run"}
        metadata = export_metadata(
            conn,
            snapshot_ids=snapshots,
            run_ids=runs,
            filters=filters,
            admx=admx,
            comparator=comparator,
        )
        for chunk in render_export(
            ExportDocument(
                view,
                metadata,
                sections,
                include_audit=True,
                secrets=tuple(
                    sorted(
                        set(snapshot_secrets(conn, cast(list[int], metadata["snapshot_ids"])))
                        | set(comparator_secrets)
                    )
                ),
            ),
            args.format,
        ):
            sys.stdout.write(chunk)
    finally:
        conn.close()
