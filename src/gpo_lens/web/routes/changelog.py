"""Changelog route.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, preventing synchronous SQLite from blocking the event loop
(Plan 022 WI-1).
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

from gpo_lens import queries
from gpo_lens import store as _store
from gpo_lens.exports import ExportSection, export_context
from gpo_lens.safe_output import safe_data
from gpo_lens.web._helpers import get_ro_conn
from gpo_lens.web.auth import Permission, Principal, requires
from gpo_lens.web.routes.export import view_export


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/changelog", response_class=HTMLResponse, name="changelog")
    def changelog(
        request: Request,
        format: str = "",
        snap_a: str = "",
        snap_b: str = "",
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> Response:
        conn = get_ro_conn(app.state.db_path)
        try:
            conn.execute("BEGIN")
            snapshots = _store.list_snapshots(conn)
            entries: list[queries.ChangelogEntry] = []
            settings_changes: list[queries.SnapshotSettingChange] = []
            snap_a_id = int(snap_a) if snap_a.isdigit() else None
            snap_b_id = int(snap_b) if snap_b.isdigit() else None
            if snap_a_id is not None and snap_b_id is not None:
                entries = queries.snapshot_changelog(conn, snap_a_id, snap_b_id)
                settings_changes = queries.snapshot_settings_diff(conn, snap_a_id, snap_b_id)
            context = export_context(
                conn,
                snapshot_ids=[s for s in (snap_a_id, snap_b_id) if s is not None],
                admx=app.state.admx,
            )
        finally:
            conn.close()

        if format:
            return view_export(
                request,
                _principal,
                "Snapshot diff",
                (
                    ExportSection("changelog", entries),
                    ExportSection("settings_diff", settings_changes),
                ),
                format=format,
                snapshot_ids=[s for s in (snap_a_id, snap_b_id) if s is not None],
                context=context,
                filters={"snap_a": snap_a_id, "snap_b": snap_b_id},
            )

        return templates.TemplateResponse(
            request,
            "changelog.html",
            {
                "request": request,
                "snapshots": snapshots,
                "snap_a": snap_a_id,
                "snap_b": snap_b_id,
                "entries": safe_data(entries, secrets=context.secrets),
                "settings_changes": safe_data(settings_changes, secrets=context.secrets),
                "admx": app.state.admx,
            },
        )
