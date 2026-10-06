"""Export (data download) routes — WI-027.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, preventing synchronous SQLite from blocking the event loop
(Plan 022 WI-1).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import datetime
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from gpo_lens.exports import ExportContext, ExportSection, export_context, occurrence_run_ids
from gpo_lens.safe_output import safe_data, secret_values
from gpo_lens.web._helpers import (
    csv_response,
    get_estate,
    get_ro_conn,
    json_attachment,
)
from gpo_lens.web.auth import Permission, Principal, requires

if TYPE_CHECKING:
    from gpo_lens.model import Estate


def _export_chunks(lines: Iterable[str], size: int = 64 * 1024) -> Iterator[bytes]:
    """Bound HTTP buffers and threadpool handoffs while retaining exact UTF-8 bytes.

    The core renderer remains line-lazy. Starlette hands synchronous iterators
    to a worker for every yield, so sending each field separately is costly.
    Split oversized lines too; never buffer the complete artifact.
    """
    if size < 1:
        raise ValueError("chunk size must be positive")
    buffer = bytearray()
    for line in lines:
        data = line.encode("utf-8")
        offset = 0
        while offset < len(data):
            end = min(len(data), offset + size - len(buffer))
            buffer.extend(data[offset:end])
            offset = end
            if len(buffer) == size:
                yield bytes(buffer)
                buffer.clear()
    if buffer:
        yield bytes(buffer)


def register(app: FastAPI, templates: Jinja2Templates) -> None:
    # ------------------------------------------------------------------
    # Export (WI-027) — read-only data downloads for analysts who want the
    # safe query results without dropping to the CLI. All require VIEW permission, the
    # same as the pages they mirror. Markdown/CSV preserve the view URL filters.
    # Legacy JSON endpoints retain their existing shapes.
    # ------------------------------------------------------------------

    @app.get("/export/findings", name="export_findings")
    def export_findings(
        request: Request,
        format: str = "csv",
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> Response:
        from gpo_lens.queries import estate_doctor
        from gpo_lens.store import load_estate

        if format in ("md", "csv"):
            params = dict(request.query_params)
            params["format"] = format
            return RedirectResponse(
                str(request.url_for("findings_inbox")) + "?" + urlencode(params), status_code=302
            )
        if format != "json":
            raise HTTPException(status_code=400, detail="format must be md, csv or json")

        conn = get_ro_conn(app.state.db_path)
        try:
            try:
                estate = load_estate(conn)
                findings = estate_doctor(estate)
            except ValueError:
                findings = []
        finally:
            conn.close()

        return json_attachment(safe_data(findings), "gpo-lens-findings.json")

    @app.get("/export/gpo/{gpo_id}", name="export_gpo")
    def export_gpo(
        request: Request,
        gpo_id: str,
        format: str = "json",
        _principal: Principal = Depends(requires(Permission.VIEW)),
        estate: Estate = Depends(get_estate),
    ) -> Response:
        from gpo_lens.normalize import canonical_guid

        # New human exports use the same dossier query; legacy JSON keeps its shape.
        if format in ("md", "csv"):
            params = dict(request.query_params)
            params["format"] = format
            return RedirectResponse(
                str(request.url_for("gpo_detail", gpo_id=gpo_id)) + "?" + urlencode(params),
                status_code=302,
            )
        if format != "json":
            raise HTTPException(status_code=400, detail="format must be md, csv or json")

        try:
            gpo_id = canonical_guid(gpo_id)
        except ValueError:
            raise HTTPException(status_code=404, detail="Invalid GPO ID") from None

        gpo = estate.gpo_by_id(gpo_id)
        if gpo is None:
            raise HTTPException(status_code=404, detail="GPO not found")

        payload = safe_data(gpo)
        return json_attachment(payload, f"gpo-lens-{gpo_id}.json")

    @app.get("/export/ou/{path:path}", name="export_ou")
    def export_ou(
        request: Request,
        path: str,
        format: str = "csv",
        _principal: Principal = Depends(requires(Permission.VIEW)),
        estate: Estate = Depends(get_estate),
    ) -> Response:
        from gpo_lens import queries

        if format not in ("csv", "json"):
            raise HTTPException(status_code=400, detail="format must be 'csv' or 'json'")

        target_som = None
        for som in estate.soms:
            if som.path.lower() == path.lower():
                target_som = som
                break
        if target_som is None:
            raise HTTPException(status_code=404, detail="OU not found")

        settings = queries.settings_at_som(estate, target_som.path)
        if format == "json":
            payload = safe_data(settings, secrets=secret_values(estate.gpos))
            return json_attachment(payload, "gpo-lens-ou-settings.json")
        # default: csv
        settings = safe_data(settings, secrets=secret_values(estate.gpos))
        rows = [
            [
                s["cse"],
                s["side"],
                s["identity"],
                s["display_name"],
                s["display_value"],
                s["winner_gpo_id"],
                s["winner_gpo_name"],
                ", ".join(f"{name}={val}" for name, val in s["overridden_by"]),
                "yes" if s["enforced"] else "no",
            ]
            for s in settings
        ]
        return csv_response(
            rows,
            [
                "cse",
                "side",
                "identity",
                "display_name",
                "display_value",
                "winner_gpo_id",
                "winner_gpo_name",
                "overridden_by",
                "enforced",
            ],
            "gpo-lens-ou-settings.csv",
        )

    @app.get("/accepted-risks", name="accepted_risks")
    def risk_register(
        request: Request,
        format: str = "",
        as_of: datetime | None = None,
        category: str = "",
        severity: str = "",
        q: str = "",
        principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> Response:
        from gpo_lens.exports import ExportSection
        from gpo_lens.findings import accepted_risk_register
        from gpo_lens.web._helpers import base_qs, paginate, parse_pagination

        if as_of is not None and (as_of.tzinfo is None or as_of.utcoffset() is None):
            raise HTTPException(status_code=422, detail="as_of must include a UTC offset")
        conn = get_ro_conn(app.state.db_path)
        try:
            conn.execute("BEGIN")
            risks = accepted_risk_register(conn, as_of=as_of)
            context = export_context(
                conn,
                run_ids=occurrence_run_ids(conn, (r.occurrence_id for r in risks)),
                admx=app.state.admx,
            )
        finally:
            conn.close()
        q = q.strip()[:200]
        risks = [
            r
            for r in risks
            if (not category or r.category == category)
            and (not severity or r.severity == severity)
            and (not q or q.lower() in (r.summary + " " + r.category).lower())
        ]
        page, per_page, per_page_raw = parse_pagination(request)
        risks, pag = paginate(risks, page, per_page, per_page_raw)
        if format:
            return view_export(
                request,
                principal,
                "Accepted risks",
                (ExportSection("accepted_risks", risks),),
                format=format,
                context=context,
                filters={
                    "as_of": as_of.isoformat() if as_of else "current triage state",
                    "category": category,
                    "severity": severity,
                    "q": q,
                    "page": pag["page"] if pag else 1,
                    "per_page": per_page_raw,
                },
            )
        return templates.TemplateResponse(
            request,
            "accepted_risks.html",
            {
                "request": request,
                "risks": safe_data(
                    risks, include_audit=principal.has(Permission.TRIAGE), secrets=context.secrets
                ),
                "can_triage": principal.has(Permission.TRIAGE),
                "pag": pag,
                "f_base_qs": base_qs(request, "page", "per_page"),
                "filters": {
                    "category": category,
                    "severity": severity,
                    "q": q,
                    "as_of": as_of.isoformat() if as_of else "",
                },
            },
        )

    @app.get("/setting", name="setting_detail")
    def setting_detail(
        request: Request,
        identity: str,
        cse: str = "",
        side: str = "",
        snapshot: int | None = None,
        format: str = "",
        principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> Response:
        from gpo_lens.exports import ExportSection, setting_payload
        from gpo_lens.store import list_snapshots, load_estate

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
        rows = setting_payload(estate, identity, cse=cse, side=side, admx=app.state.admx)
        selected_snapshot = snapshot if snapshot is not None else snapshots[0][0]
        if format:
            return view_export(
                request,
                principal,
                "Setting",
                (ExportSection("settings", rows),),
                format=format,
                snapshot_ids=[selected_snapshot],
                context=context,
                filters={"identity": identity, "cse": cse, "side": side},
            )
        return templates.TemplateResponse(
            request,
            "setting_detail.html",
            {
                "request": request,
                "identity": safe_data(identity),
                "ledger": rows,
                "snapshot_id": selected_snapshot,
            },
        )


def view_export(
    request: Request,
    principal: Principal,
    title: str,
    sections: tuple[ExportSection, ...],
    *,
    format: str,
    snapshot_ids: list[int] | None = None,
    run_ids: list[int] | None = None,
    filters: dict[str, object] | None = None,
    comparator: object = None,
    context: ExportContext | None = None,
) -> Response:
    """Export the view's already-computed, filtered query result."""
    from fastapi.responses import StreamingResponse

    from gpo_lens.exports import ExportDocument, render_export

    if format not in {"md", "csv"}:
        raise HTTPException(status_code=400, detail="format must be md or csv")
    if context is None:
        conn = get_ro_conn(request.app.state.db_path)
        try:
            conn.execute("BEGIN")
            context = export_context(
                conn,
                snapshot_ids=snapshot_ids,
                run_ids=run_ids,
                admx=request.app.state.admx,
                comparator=comparator,
            )
        finally:
            conn.close()
    metadata = {**context.metadata, "filters": filters or {}}
    secrets = context.secrets
    document = ExportDocument(title, metadata, sections, principal.has(Permission.TRIAGE), secrets)
    filename = "gpo-lens-" + title.lower().replace(" ", "-") + "." + format
    return StreamingResponse(
        _export_chunks(render_export(document, format)),
        media_type="text/csv" if format == "csv" else "text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
