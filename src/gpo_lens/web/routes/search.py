"""Estate-wide settings search — "which GPOs set X?" (WI-082).

The query layer (``queries.who_sets`` / ``queries.search``) is otherwise
CLI-only. This surfaces it in the web UI: a settings-scoped search over
identity / display name / value, grouped by GPO with deep-links, plus CSE and
side facets. Mirrors the Conflicts/Inventory route shape (filter bar +
pagination). An empty query renders a prompt rather than dumping the estate.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, preventing synchronous SQLite from blocking the event loop
(Plan 022 WI-1).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

from gpo_lens.exports import ExportSection, export_context
from gpo_lens.safe_output import safe_data
from gpo_lens.web._helpers import (
    _MAX_SEARCH_LEN,
    base_qs,
    get_ro_conn,
    paginate,
    parse_pagination,
)
from gpo_lens.web.auth import Permission, Principal, requires
from gpo_lens.web.routes.export import view_export

if TYPE_CHECKING:
    from gpo_lens.model import Setting


@dataclass(frozen=True)
class _GpoGroup:
    """Matching settings for one GPO (the unit of pagination)."""

    gpo_id: str
    gpo_name: str
    results: list[Setting]


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/search", response_class=HTMLResponse, name="search")
    def search_page(
        request: Request,
        format: str = "",
        q: str = "",
        cse: str = "",
        side: str = "",
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> Response:
        from gpo_lens.queries import who_sets
        from gpo_lens.store import load_estate

        q = (q or "").strip()[:_MAX_SEARCH_LEN]
        groups: list[_GpoGroup] = []
        cse_facets: list[tuple[str, int]] = []
        side_facets: list[tuple[str, int]] = []
        total_hits = 0
        context = None

        if q:
            conn = get_ro_conn(app.state.db_path)
            try:
                try:
                    conn.execute("BEGIN")
                    estate = load_estate(conn)
                    context = export_context(conn, admx=app.state.admx)
                    names = estate.gpo_names
                    settings = who_sets(estate, q)
                    total_hits = len(settings)
                    # Facet counts come from the full hit set (pre-facet), so the
                    # chips show the full breadth even while one is active.
                    cse_facets = sorted(Counter(s.cse for s in settings).items())
                    side_facets = sorted(Counter(s.side for s in settings).items())
                    if cse:
                        settings = [s for s in settings if s.cse == cse]
                    if side:
                        settings = [s for s in settings if s.side == side]
                    by_gpo: dict[str, _GpoGroup] = {}
                    for s in settings:
                        grp = by_gpo.get(s.gpo_id)
                        if grp is None:
                            grp = _GpoGroup(s.gpo_id, names.get(s.gpo_id, s.gpo_id), [])
                            by_gpo[s.gpo_id] = grp
                        grp.results.append(s)
                    groups = sorted(by_gpo.values(), key=lambda g: g.gpo_name.lower())
                except ValueError:
                    groups = []
            finally:
                conn.close()

        page, per_page_int, per_page_raw = parse_pagination(request)
        page_groups, pag = paginate(groups, page, per_page_int, per_page_raw)
        search_qs = base_qs(request, "page", "per_page")

        if format:
            return view_export(
                request,
                _principal,
                "Settings search",
                (ExportSection("settings", (s for g in page_groups for s in g.results)),),
                format=format,
                context=context,
                snapshot_ids=[] if context is None else None,
                filters={
                    "q": q,
                    "cse": cse,
                    "side": side,
                    "page": pag["page"] if pag else 1,
                    "per_page": per_page_raw,
                },
            )

        return templates.TemplateResponse(
            request,
            "search.html",
            {
                "request": request,
                "groups": safe_data(page_groups),
                "f_q": q,
                "f_cse": cse,
                "f_side": side,
                "total_hits": total_hits,
                "filtered_hits": sum(len(g.results) for g in groups),
                "gpo_count": len(groups),
                "cse_facets": cse_facets,
                "side_facets": side_facets,
                "f_base_qs": search_qs,
                "pag": pag,
            },
        )
