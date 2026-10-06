"""Explore external dependencies using the shared deterministic export layer."""

from fastapi import Depends, FastAPI, Request
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates

from gpo_lens import store
from gpo_lens.dependencies import external_dependencies
from gpo_lens.exports import ExportSection, export_context
from gpo_lens.model import Estate
from gpo_lens.safe_output import safe_data
from gpo_lens.web._helpers import get_ro_conn
from gpo_lens.web.auth import Permission, Principal, requires
from gpo_lens.web.routes.export import view_export


def register(app: FastAPI, templates: Jinja2Templates) -> None:
    @app.get("/dependencies", name="dependencies")
    def dependencies_page(
        request: Request,
        server: str = "",
        format: str = "",
        principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> Response:
        conn = get_ro_conn(app.state.db_path)
        try:
            conn.execute("BEGIN")
            estate = store.load_estate(conn) if store.list_snapshots(conn) else Estate(gpos=[])
            groups = external_dependencies(estate, server=server)
            context = export_context(conn, admx=app.state.admx)
        finally:
            conn.close()
        if format:
            return view_export(
                request,
                principal,
                "External dependencies",
                (
                    ExportSection("servers", groups),
                    ExportSection("dependencies", (r for g in groups for r in g.dependencies)),
                ),
                format=format,
                context=context,
                filters={"server": server},
            )
        return templates.TemplateResponse(
            request,
            "dependencies.html",
            {
                "request": request,
                "groups": safe_data(groups, secrets=context.secrets),
                "server": safe_data(server, secrets=context.secrets),
                "dependency_count": sum(g.dependency_count for g in groups),
            },
        )
