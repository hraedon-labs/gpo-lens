"""Golden-backup diff routes.

DB-touching handlers are plain ``def`` (not ``async def``) so FastAPI runs them
in its threadpool, preventing synchronous SQLite from blocking the event loop
(Plan 022 WI-1). ``golden_diff_post`` stays ``async def`` because it streams
the upload body via ``await``.
"""

from __future__ import annotations

import asyncio
import logging
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

import gpo_lens.web.app as _app_module
from gpo_lens import ingest as _ingest
from gpo_lens import queries
from gpo_lens import store as _store
from gpo_lens.exports import ExportSection, export_context
from gpo_lens.safe_output import safe_data
from gpo_lens.web._helpers import get_ro_conn, stream_upload_to_file
from gpo_lens.web.app import _audit
from gpo_lens.web.auth import Permission, Principal, requires
from gpo_lens.web.page_narration import make_action
from gpo_lens.web.routes.export import view_export

_logger = logging.getLogger(__name__)


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/golden-diff", response_class=HTMLResponse, name="golden_diff_get")
    def golden_diff_get(
        request: Request,
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "golden_diff.html",
            {"request": request, "diff_entries": [], "summary": None, "error": None},
        )

    @app.post(
        "/golden-diff",
        response_class=HTMLResponse,
        response_model=None,
        name="golden_diff_post",
    )
    async def golden_diff_post(
        request: Request,
        file: UploadFile = File(...),
        format: str = Form(""),
        _principal: Principal = Depends(requires(Permission.INGEST)),
    ) -> Response:
        from gpo_lens.model import Estate as _Estate

        try:
            with TemporaryDirectory() as tmpdir:
                zip_path = Path(tmpdir) / "golden.zip"
                if await stream_upload_to_file(file, zip_path, _app_module._MAX_UPLOAD_BYTES):
                    return templates.TemplateResponse(
                        request,
                        "golden_diff.html",
                        {
                            "request": request,
                            "diff_entries": [],
                            "summary": None,
                            "error": "Upload exceeds 500MB limit.",
                        },
                        status_code=413,
                    )
                golden_gpos = await asyncio.to_thread(_ingest.load_baseline_from_zip, zip_path)

            def _compute_diff():  # type: ignore[no-untyped-def]
                golden_estate = _Estate(domain="golden", gpos=golden_gpos)
                conn = get_ro_conn(app.state.db_path)
                try:
                    conn.execute("BEGIN")
                    snapshot_ids = [s[0] for s in _store.list_snapshots(conn)[:1]]
                    snapshot_id = snapshot_ids[0] if snapshot_ids else None
                    estate = _store.load_estate(conn, snapshot_id)
                    context = export_context(
                        conn,
                        snapshot_ids=snapshot_ids,
                        admx=app.state.admx,
                        comparator=golden_estate,
                    )
                finally:
                    conn.close()
                diff = queries.golden_diff(estate, golden_estate, admx=app.state.admx)
                live_names = {g.name.lower() for g in estate.gpos}
                golden_names = {g.name.lower() for g in golden_estate.gpos}
                summ = queries.golden_diff_summary(
                    diff, matched_gpo_count=len(live_names & golden_names)
                )
                return diff, summ, golden_estate, snapshot_ids, context

            diff_entries, summary, comparator, snapshot_ids, context = await asyncio.to_thread(
                _compute_diff
            )
            detail = (
                f"{summary.gpos_matched} matched, {summary.gpos_added} added, "
                f"{summary.gpos_removed} removed"
            )
            _audit("golden_diff", _principal, "success", detail, request)
        except (
            ValueError,
            zipfile.BadZipFile,
            FileNotFoundError,
            OSError,
            NotImplementedError,
            RuntimeError,
            MemoryError,
        ) as exc:
            _logger.warning("Invalid golden zip: %s", exc)
            _audit("golden_diff", _principal, "failure", type(exc).__name__, request)
            return templates.TemplateResponse(
                request,
                "golden_diff.html",
                {
                    "request": request,
                    "diff_entries": [],
                    "summary": None,
                    "error": "Invalid golden zip file.",
                },
            )

        if format:
            return view_export(
                request,
                _principal,
                "Golden diff",
                (ExportSection("comparison", diff_entries),),
                format=format,
                snapshot_ids=snapshot_ids,
                comparator=comparator,
                context=context,
                filters={
                    "comparison": "golden",
                    "evaluation": "ad hoc; no persisted comparison run",
                },
            )
        diff_entries = safe_data(diff_entries, secrets=context.secrets)

        return templates.TemplateResponse(
            request,
            "golden_diff.html",
            {
                "request": request,
                "narration_payload": make_action(
                    request,
                    _principal,
                    "golden_comparison",
                    snapshot_ids,
                    {"comparisons": len(diff_entries)},
                ),
                "diff_entries": diff_entries,
                "summary": summary,
                "error": None,
            },
        )
