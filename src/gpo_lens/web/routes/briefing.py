"""Briefing — the deterministic "do I need to care today?" page (Plan 025 WI-2).

The facts and prose come from ``gpo_lens.briefing``, which is web-free and
golden-tested. This module's only jobs are choosing the snapshot, turning vital
keys into destinations, and rendering — so the prose can never drift between the
page and its goldens.

Plan 027 Phase 2 sequences the nav migration separately, so this ships as a new
destination rather than replacing the dashboard as home.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, preventing synchronous SQLite from blocking the event loop.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

from gpo_lens.exports import ExportSection, export_context
from gpo_lens.safe_output import safe_data
from gpo_lens.web._helpers import get_ro_conn
from gpo_lens.web.auth import Permission, Principal, requires
from gpo_lens.web.routes.export import view_export

# Plan 025 WI-2 forbids an unlinked stat tile. Every key in
# ``briefing.VITAL_KEYS`` must appear here; the template asserts nothing, it
# simply cannot render a tile whose destination is missing.
_VITAL_TARGETS: dict[str, tuple[str, dict[str, str]]] = {
    "critical_findings": (
        "findings_inbox",
        {"severity": "critical", "lifecycle": "all", "triage": "all"},
    ),
    "active_findings": (
        "findings_inbox",
        {"lifecycle": "all", "triage": "all"},
    ),
    "coverage_gaps": (
        "findings_inbox",
        {"category": "coverage_gap", "lifecycle": "all", "triage": "all"},
    ),
    "accepted_risks": (
        "findings_inbox",
        {"triage": "accepted_risk", "lifecycle": "all"},
    ),
    "gpo_count": ("gpo_list", {}),
}


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/briefing", response_class=HTMLResponse, name="briefing")
    def briefing_page(
        request: Request,
        snapshot: int | None = None,
        format: str = "",
        as_of: datetime | None = None,
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> Response:
        from gpo_lens.briefing import VITAL_KEYS, briefing_lines, build_briefing
        from gpo_lens.store import list_snapshots

        if as_of is not None and (as_of.tzinfo is None or as_of.utcoffset() is None):
            raise HTTPException(status_code=422, detail="as_of must include a UTC offset")
        conn = get_ro_conn(app.state.db_path)
        try:
            conn.execute("BEGIN")
            briefing = build_briefing(conn, as_of_snapshot=snapshot, now=as_of)
            snapshots = list_snapshots(conn)
            context = export_context(
                conn, snapshot_ids=[briefing.snapshot_id] if briefing else [], admx=app.state.admx
            )
        finally:
            conn.close()

        # A missing snapshot id is a bad link, not an empty estate — tell the
        # two apart rather than rendering "no data" for a typo.
        if briefing is None and snapshot is not None and snapshots:
            return HTMLResponse("Snapshot not found", status_code=404)

        if format:
            sections = (
                ExportSection("briefing", (briefing,)),
                ExportSection("sentences", briefing_lines(briefing) if briefing else ()),
            )
            return view_export(
                request,
                _principal,
                "Briefing",
                sections,
                format=format,
                snapshot_ids=[briefing.snapshot_id] if briefing else [],
                context=context,
                filters={
                    "snapshot": snapshot,
                    "as_of": as_of.isoformat() if as_of else "current triage state",
                },
            )

        tiles = []
        if briefing is not None:
            missing = [v.key for v in briefing.vitals if v.key not in _VITAL_TARGETS]
            if missing:  # pragma: no cover - guarded by test_vital_keys_all_linked
                raise RuntimeError(f"briefing vitals with no link target: {sorted(missing)}")
            for vital in briefing.vitals:
                name, params = _VITAL_TARGETS[vital.key]
                href = str(request.url_for(name))
                if params:
                    href += "?" + "&".join(f"{k}={v}" for k, v in params.items())
                tiles.append(
                    {
                        "label": vital.label,
                        "value": vital.value,
                        "tone": vital.tone,
                        "href": href,
                    }
                )

        return templates.TemplateResponse(
            request,
            "briefing.html",
            {
                "request": request,
                "briefing": {
                    **safe_data(
                        briefing,
                        include_audit=_principal.has(Permission.TRIAGE),
                        secrets=context.secrets,
                    ),
                    "has_change": briefing.has_change,
                }
                if briefing
                else None,
                "lines": safe_data(briefing_lines(briefing), secrets=context.secrets)
                if briefing
                else (),
                "tiles": tiles,
                "snapshots": snapshots,
                "selected_snapshot": snapshot,
                "vital_keys": VITAL_KEYS,
            },
        )
