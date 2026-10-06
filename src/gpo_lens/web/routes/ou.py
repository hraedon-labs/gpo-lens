"""OU list and detail routes.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, preventing synchronous SQLite from blocking the event loop
(Plan 022 WI-1).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from gpo_lens import queries, topology
from gpo_lens.web._helpers import (
    _VALID_OU_SORTS,
    _VALID_OU_TYPES,
    base_qs,
    cse_facets,
    filter_settings,
    filter_soms,
    get_ro_conn,
    paginate,
    parse_pagination,
)
from gpo_lens.web.auth import Permission, Principal, requires
from gpo_lens.web.page_narration import make_action

if TYPE_CHECKING:
    from gpo_lens.model import Estate


def _estate_for_ou(request: Request) -> Estate:
    from gpo_lens.store import list_snapshots, load_estate

    conn = get_ro_conn(request.app.state.db_path)
    try:
        snapshots = list_snapshots(conn)
        snapshot_id = snapshots[0][0] if snapshots else None
        request.state.ou_snapshot_id = snapshot_id
        return load_estate(conn, snapshot_id)
    finally:
        conn.close()


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/ou", response_class=HTMLResponse, name="ou_list")
    def ou_list(
        request: Request,
        q: str = "",
        type: str = "",
        sort: str = "name",
        _principal: Principal = Depends(requires(Permission.VIEW)),
        estate: Estate = Depends(_estate_for_ou),
    ) -> HTMLResponse:
        if type and type not in _VALID_OU_TYPES:
            type = ""
        if sort not in _VALID_OU_SORTS:
            sort = "name"
        all_soms = list(estate.soms)
        filtered = filter_soms(all_soms, q, type, sort)

        page, per_page_int, per_page_raw = parse_pagination(request)
        page_soms, pag = paginate(filtered, page, per_page_int, per_page_raw)
        ou_qs = base_qs(request, "page", "per_page")
        return templates.TemplateResponse(
            request,
            "ou_list.html",
            {
                "soms": page_soms,
                "pag": pag,
                "all_soms_count": len(all_soms),
                "filtered_count": len(filtered),
                "f_q": q,
                "f_type": type,
                "f_sort": sort,
                "f_base_qs": ou_qs,
            },
        )

    @app.get("/ou/{path:path}", response_class=HTMLResponse, name="ou_detail")
    def ou_detail(
        request: Request,
        path: str,
        q: str = "",
        cse: str = "",
        _principal: Principal = Depends(requires(Permission.VIEW)),
        estate: Estate = Depends(_estate_for_ou),
    ) -> HTMLResponse:
        target_som = None
        for som in estate.soms:
            if som.path.lower() == path.lower():
                target_som = som
                break

        if target_som is None:
            raise HTTPException(status_code=404, detail="OU not found")

        all_settings = queries.settings_at_som(estate, target_som.path)
        conflicts = queries.som_conflicts(estate, target_som.path)
        caveats = queries.scope_caveats(estate, target_som.path)

        gate_pairs = topology.gate_summaries(estate, target_som.path, _som=target_som)
        effective_gpos = [eg for eg, _ in gate_pairs]

        loopback_warning = any(gs.loopback_mode for _, gs in gate_pairs)

        # WI-9: mechanism counts for the one-line caveat summary (the full
        # per-GPO detail stays in the caveats list, shown behind <details>).
        caveat_counts = {
            "security_filtered": sum(1 for _, gs in gate_pairs if gs.is_security_filtered),
            "wmi": sum(1 for _, gs in gate_pairs if gs.wmi_filter_name),
            "loopback": sum(1 for _, gs in gate_pairs if gs.loopback_mode),
            "ilt": sum(1 for _, gs in gate_pairs if gs.has_ilt),
        }
        has_site_links_caveat = topology.has_site_links(estate)

        # WI-083: CSE facet (computed from the full set so the dropdown shows
        # all CSEs even while one is selected) + text search over the table.
        facets = cse_facets(all_settings)
        settings = filter_settings(all_settings, q, cse)

        page, per_page_int, per_page_raw = parse_pagination(request)
        page_settings, pag = paginate(settings, page, per_page_int, per_page_raw)
        settings_qs = base_qs(request, "page", "per_page")

        return templates.TemplateResponse(
            request,
            "ou_detail.html",
            {
                "narration_payload": make_action(
                    request,
                    _principal,
                    "ou",
                    [request.state.ou_snapshot_id],
                    {
                        "settings": len(page_settings),
                        "settings_total": len(all_settings),
                        "effective_gpos": len(effective_gpos),
                        "conflicts": len(conflicts),
                        "scope_caveats": len(caveats),
                    },
                ),
                "som": target_som,
                "effective_gpos": effective_gpos,
                "gate_summaries": gate_pairs,
                "settings": page_settings,
                "settings_count": len(settings),
                "settings_total": len(all_settings),
                "cse_facets": facets,
                "f_q": q,
                "f_cse": cse,
                "conflicts": conflicts,
                "loopback_warning": loopback_warning,
                "caveats": caveats,
                "caveat_counts": caveat_counts,
                "has_site_links_caveat": has_site_links_caveat,
                "pag": pag,
                "base_qs": settings_qs,
                "admx": app.state.admx,
            },
        )
