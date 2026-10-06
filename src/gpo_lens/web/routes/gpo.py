"""GPO detail and danger-list routes.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, preventing synchronous SQLite from blocking the event loop
(Plan 022 WI-1).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from gpo_lens import topology
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
from gpo_lens.web.page_narration import make_action


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
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        from gpo_lens.normalize import canonical_guid
        from gpo_lens.queries import settings_ledger
        from gpo_lens.store import list_snapshots, load_estate

        try:
            gpo_id = canonical_guid(gpo_id)
        except ValueError:
            raise HTTPException(status_code=404, detail="Invalid GPO ID") from None

        conn = get_ro_conn(app.state.db_path)
        try:
            snapshots = list_snapshots(conn)
            estate = load_estate(conn, snapshots[0][0] if snapshots else None)
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
                    idx_a = {(r.side, r.cse, r.identity): r for r in ledger}
                    idx_b = {(r.side, r.cse, r.identity): r for r in other_ledger}
                    all_keys = set(idx_a) | set(idx_b)
                    for key in sorted(all_keys):
                        a = idx_a.get(key)
                        b = idx_b.get(key)
                        if a and b:
                            if a.display_value != b.display_value:
                                diff_rows.append(
                                    {
                                        "side": a.side,
                                        "cse": a.cse,
                                        "identity": a.identity,
                                        "display_name": a.admx_name or a.display_name,
                                        "change": "modified",
                                        "val_a": a.display_value,
                                        "val_b": b.display_value,
                                    }
                                )
                        elif a and not b:
                            diff_rows.append(
                                {
                                    "side": a.side,
                                    "cse": a.cse,
                                    "identity": a.identity,
                                    "display_name": a.admx_name or a.display_name,
                                    "change": "only_in_a",
                                    "val_a": a.display_value,
                                    "val_b": "",
                                }
                            )
                        elif b and not a:
                            diff_rows.append(
                                {
                                    "side": b.side,
                                    "cse": b.cse,
                                    "identity": b.identity,
                                    "display_name": b.admx_name or b.display_name,
                                    "change": "only_in_b",
                                    "val_a": "",
                                    "val_b": b.display_value,
                                }
                            )
            except ValueError:
                pass

        return templates.TemplateResponse(
            request,
            "gpo_detail.html",
            {
                "request": request,
                "narration_payload": make_action(
                    request,
                    _principal,
                    "gpo_comparison" if compare_gpo else "dossier",
                    [snapshots[0][0]] if snapshots else [],
                    {
                        "settings": len(ledger),
                        "links": len(gpo.links),
                        "findings": open_finding_count,
                        "scope_caveats": len(caveats),
                        **({"comparisons": len(diff_rows)} if compare_gpo else {}),
                    },
                ),
                "gpo": gpo,
                "settings_by_side": dict(settings_by_side),
                "disabled_sides": disabled_sides,
                "caveats": caveats,
                "ledger": ledger,
                "admx": app.state.admx,
                "sec_filter": sec_filter,
                "open_finding_count": open_finding_count,
                "snapshots": snapshots,
                "other_gpos": [
                    {"id": g.id, "name": g.name}
                    for g in sorted(estate.gpos, key=lambda g: g.name.lower())
                    if g.id != gpo_id
                ],
                "compare_gpo": compare_gpo,
                "diff_rows": diff_rows,
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
