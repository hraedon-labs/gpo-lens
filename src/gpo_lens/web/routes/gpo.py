"""GPO detail and danger-list routes.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, preventing synchronous SQLite from blocking the event loop
(Plan 022 WI-1).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

from gpo_lens import topology
from gpo_lens.exports import ExportSection, compare_ledgers, export_context, filter_ledger
from gpo_lens.safe_output import safe_data
from gpo_lens.web._helpers import (
    _MAX_SEARCH_LEN,
    _VALID_GPO_SORTS,
    _VALID_GPO_STATUS,
    base_qs,
    filter_gpos,
    get_ro_conn,
    paginate,
    parse_pagination,
)
from gpo_lens.web.auth import Permission, Principal, requires
from gpo_lens.web.routes.export import view_export


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/inventory", response_class=HTMLResponse, name="gpo_list")
    def gpo_list(
        request: Request,
        q: str = "",
        status: str = "",
        sort: str = "name",
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        from gpo_lens.store import load_estate

        conn = get_ro_conn(app.state.db_path)
        try:
            try:
                estate = load_estate(conn)
                all_gpos = list(estate.gpos)
            except ValueError:
                all_gpos = []
        finally:
            conn.close()

        if status and status not in _VALID_GPO_STATUS:
            status = ""
        if sort not in _VALID_GPO_SORTS:
            sort = "name"
        filtered = filter_gpos(all_gpos, q, status, sort)

        page, per_page_int, per_page_raw = parse_pagination(request)
        page_gpos, pag = paginate(filtered, page, per_page_int, per_page_raw)
        inv_qs = base_qs(request, "page", "per_page")
        return templates.TemplateResponse(
            request,
            "inventory.html",
            {
                "request": request,
                "gpos": page_gpos,
                "all_gpos_count": len(all_gpos),
                "filtered_count": len(filtered),
                "f_q": q,
                "f_status": status,
                "f_sort": sort,
                "f_base_qs": inv_qs,
                "pag": pag,
            },
        )

    @app.get("/gpo/{gpo_id}", response_class=HTMLResponse, name="gpo_detail")
    def gpo_detail(
        request: Request,
        gpo_id: str,
        compare: str = "",
        format: str = "",
        ledger_q: str = "",
        side: str = "",
        cse: str = "",
        snapshot: int | None = None,
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> Response:
        from gpo_lens.normalize import canonical_guid
        from gpo_lens.queries import settings_ledger
        from gpo_lens.store import list_snapshots, load_estate

        try:
            gpo_id = canonical_guid(gpo_id)
        except ValueError:
            raise HTTPException(status_code=404, detail="Invalid GPO ID") from None

        conn = get_ro_conn(app.state.db_path)
        try:
            conn.execute("BEGIN")
            snapshots = list_snapshots(conn)
            selected_snapshot = (
                snapshot if snapshot is not None else snapshots[0][0] if snapshots else None
            )
            estate = load_estate(conn, snapshot_id=selected_snapshot)
            context = export_context(
                conn,
                snapshot_ids=[selected_snapshot] if selected_snapshot is not None else [],
                admx=app.state.admx,
            )
        except ValueError:
            raise HTTPException(status_code=404, detail="Snapshot not found") from None
        finally:
            conn.close()

        gpo = estate.gpo_by_id(gpo_id)
        if gpo is None:
            raise HTTPException(status_code=404, detail="GPO not found")

        scope = topology.effective_scope(estate, gpo_id)
        caveats = scope.caveats if scope is not None else []
        sec_filter = topology.security_filtering_detail(gpo, estate)

        disabled_sides: set[str] = set()
        if not gpo.computer_enabled and any(
            s.side == "Computer" and s.from_disabled_side for s in gpo.settings
        ):
            disabled_sides.add("Computer")
        if not gpo.user_enabled and any(
            s.side == "User" and s.from_disabled_side for s in gpo.settings
        ):
            disabled_sides.add("User")

        ledger = settings_ledger(estate, gpo_id, admx=app.state.admx)

        # Read findings materialized at ingest time. Re-running every detector
        # here made dossier navigation scale with the whole estate and could
        # disagree with the lifecycle/triage inbox.
        conn = get_ro_conn(app.state.db_path)
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM finding WHERE resolved_in_snapshot IS NULL AND gpo_id = ?",
                (gpo_id,),
            ).fetchone()
            open_finding_count = int(row[0]) if row is not None else 0
        finally:
            conn.close()

        # Group settings by side, then by CSE for the legacy table view
        settings_by_side: dict[str, dict[str, list[object]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for s in gpo.settings:
            settings_by_side[s.side][s.cse].append(s)

        # GPO-vs-GPO diff (WI-2): compare with another GPO
        diff_rows: list[dict[str, str]] = []
        compare_gpo = None
        if compare:
            try:
                compare_id = canonical_guid(compare)
                compare_gpo = estate.gpo_by_id(compare_id)
                if compare_gpo is not None:
                    other_ledger = settings_ledger(estate, compare_id, admx=app.state.admx)
                    diff_rows = compare_ledgers(ledger, other_ledger)
            except ValueError:
                pass

        # Redact once across the dossier and ledger, so flattened copies of raw
        # credentials have the same mask in every presentation.
        safe = safe_data(
            {
                "gpo": gpo,
                "ledger": ledger,
                "diff_rows": diff_rows,
                "settings_by_side": dict(settings_by_side),
                "sec_filter": sec_filter,
                "caveats": caveats,
                "comparison_source": compare_gpo,
            },
            include_audit=_principal.has(Permission.TRIAGE),
        )
        ledger_q = ledger_q.strip()[:_MAX_SEARCH_LEN]
        safe["ledger"] = filter_ledger(safe["ledger"], q=ledger_q, side=side, cse=cse)
        safe["gpo"]["computer_version_skew"] = gpo.computer_version_skew
        safe["gpo"]["user_version_skew"] = gpo.user_version_skew
        if format:
            sections: tuple[ExportSection, ...] = (
                ExportSection(
                    "dossier",
                    (
                        {
                            k: v
                            for k, v in safe["gpo"].items()
                            if k not in {"settings", "links", "delegation", "sysvol_path"}
                        },
                    ),
                ),
                ExportSection("links", safe["gpo"]["links"]),
                ExportSection("delegation", safe["gpo"]["delegation"]),
                ExportSection("settings_ledger", safe["ledger"]),
                ExportSection(
                    "scope",
                    ({"caveats": safe["caveats"], "security_filtering": safe["sec_filter"]},),
                ),
                ExportSection("gpo_comparison", safe["diff_rows"]),
            )
            if request.query_params.get("view") == "ledger":
                sections = (sections[3],)
            elif request.query_params.get("view") == "comparison":
                sections = (sections[-1],)
            return view_export(
                request,
                _principal,
                "GPO dossier",
                sections,
                format=format,
                snapshot_ids=[selected_snapshot] if selected_snapshot is not None else [],
                context=context,
                filters={
                    "gpo_id": gpo_id,
                    "compare": compare,
                    "ledger_q": ledger_q,
                    "side": side,
                    "cse": cse,
                    "view": request.query_params.get("view", "dossier"),
                },
            )
        return templates.TemplateResponse(
            request,
            "gpo_detail.html",
            {
                "request": request,
                "gpo": safe["gpo"],
                "settings_by_side": safe["settings_by_side"],
                "disabled_sides": disabled_sides,
                "caveats": safe["caveats"],
                "ledger": safe["ledger"],
                "f_ledger_q": ledger_q,
                "admx": app.state.admx,
                "sec_filter": safe["sec_filter"],
                "open_finding_count": open_finding_count,
                "snapshots": snapshots,
                "other_gpos": [
                    {"id": g.id, "name": g.name}
                    for g in sorted(estate.gpos, key=lambda g: g.name.lower())
                    if g.id != gpo_id
                ],
                "compare_gpo": compare_gpo,
                "diff_rows": safe["diff_rows"],
                "f_compare": compare,
            },
        )

    @app.get("/danger", response_class=HTMLResponse, name="danger_list")
    def danger_list(
        request: Request,
        severity: str = "",
        q: str = "",
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        from gpo_lens.danger import danger_findings
        from gpo_lens.store import load_estate

        conn = get_ro_conn(app.state.db_path)
        try:
            try:
                estate = load_estate(conn)
                all_findings = danger_findings(estate, admx=app.state.admx)
                resolvable_gpo_ids = {g.id for g in estate.gpos}
            except ValueError:
                all_findings = []
                resolvable_gpo_ids = set()
        finally:
            conn.close()

        filtered: list[Any] = all_findings
        if severity and severity != "all":
            wanted = {s.strip() for s in severity.split(",") if s.strip()}
            filtered = [f for f in filtered if f.severity in wanted]
        q = (q or "")[:_MAX_SEARCH_LEN]
        if q:
            needle = q.lower()
            filtered = [
                f
                for f in filtered
                if needle in (f.gpo_name or "").lower()
                or needle in (f.title or "").lower()
                or needle in (f.check_id or "").lower()
            ]

        page, per_page_int, per_page_raw = parse_pagination(request)
        page_findings, pag = paginate(filtered, page, per_page_int, per_page_raw)
        base_qs_val = base_qs(request, "page", "per_page")

        return templates.TemplateResponse(
            request,
            "danger_list.html",
            {
                "request": request,
                "findings": page_findings,
                "all_findings_count": len(all_findings),
                "filtered_findings_count": len(filtered),
                "resolvable_gpo_ids": resolvable_gpo_ids,
                "f_severity": severity,
                "f_q": q,
                "f_base_qs": base_qs_val,
                "pag": pag,
            },
        )
