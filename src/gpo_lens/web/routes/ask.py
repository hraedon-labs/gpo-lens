"""Ask (narration) routes.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, preventing synchronous SQLite from blocking the event loop
(Plan 022 WI-1).
"""

from __future__ import annotations

import dataclasses
import os

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from gpo_lens import events as _events
from gpo_lens import queries
from gpo_lens.display import serialize_result
from gpo_lens.query_dispatch import (
    QUERY_OPTIONAL_PARAMS,
    VALID_QUERIES,
    dispatch_query,
    validate_params,
)
from gpo_lens.web._helpers import get_ro_conn, get_rw_conn, sanitize_question
from gpo_lens.web.auth import Permission, Principal, requires
from gpo_lens.web.page_narration import make_action


def _narration_available() -> bool:
    return bool(os.environ.get("GPO_LENS_API_KEY"))


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/ask", response_class=HTMLResponse, name="ask_get")
    def ask_get(
        request: Request,
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "ask.html",
            {
                "request": request,
                "narration_available": _narration_available(),
            },
        )

    @app.post("/ask", response_class=HTMLResponse, response_model=None, name="ask_post")
    def ask_post(
        request: Request,
        question: str = Form(...),
        principal: Principal = Depends(requires(Permission.NARRATE)),
    ) -> HTMLResponse:
        from gpo_lens.detection import mask_cpassword
        from gpo_lens.narration import NarrationUnavailable, route_question
        from gpo_lens.store import list_snapshots, load_estate

        narration_available = _narration_available()
        sanitized = sanitize_question(question)
        narration_payload: str | None = None
        facts: object = None
        error: str | None = None

        if not narration_available:
            error = (
                "Narration is not configured. Set the GPO_LENS_LLM_ENDPOINT "
                "and GPO_LENS_API_KEY environment variables to enable "
                "AI-powered analysis."
            )
        else:
            conn = get_ro_conn(app.state.db_path)
            try:
                snapshot_ids = [s[0] for s in list_snapshots(conn)[:1]]
                estate = load_estate(conn, snapshot_ids[0] if snapshot_ids else None)
            finally:
                conn.close()

            try:
                routing = route_question(
                    f"--- USER QUESTION START ---\n{sanitized}\n--- USER QUESTION END ---"
                )
            except NarrationUnavailable as exc:
                error = str(exc)
                routing = None

            if routing is not None and "error" in routing:
                error = f"Cannot answer: {routing.get('reason', 'unknown')}"
                routing = None

            if routing is not None:
                query_name = str(routing["query"])
                raw_params = routing.get("params", {})
                params: dict[str, object] = dict(raw_params) if isinstance(raw_params, dict) else {}
                params = {k: v for k, v in params.items() if k != "estate"}
                if query_name in VALID_QUERIES:
                    try:
                        call_kw = validate_params(query_name, {"estate": estate, **params})
                    except ValueError as exc:
                        error = str(exc)
                    if error is None:
                        if "admx" in QUERY_OPTIONAL_PARAMS.get(query_name, []):
                            call_kw["admx"] = app.state.admx
                        query_result: object = dispatch_query(query_name, **call_kw)
                        if query_name == "cpassword_scan":
                            hits: list[queries.CpasswordHit] = query_result  # type: ignore[assignment]
                            query_result = [
                                dataclasses.replace(
                                    hit,
                                    cpassword=mask_cpassword(hit.cpassword),
                                )
                                for hit in hits
                            ]
                        serialized = serialize_result(query_result)
                        # Routing sees the user's question, never estate evidence.
                        # Deterministic results render immediately after routing;
                        # optional narration is a separate checked page action.
                        narration_payload = make_action(
                            request,
                            principal,
                            f"ask:{query_name}",
                            snapshot_ids,
                            {"results": len(serialized) if isinstance(serialized, list) else 1},
                        )
                        facts = serialized
                else:
                    error = f"Query '{query_name}' not implemented"

        outcome = (
            "success"
            if facts is not None
            else ("not_configured" if not narration_available else "error")
        )
        rw_conn = get_rw_conn(app.state.db_path)
        try:
            _events.append_event(
                rw_conn,
                "audit.narrate",
                {"principal": principal.name, "question": sanitized, "outcome": outcome},
            )
        finally:
            rw_conn.close()

        return templates.TemplateResponse(
            request,
            "ask.html",
            {
                "request": request,
                "narration_available": narration_available,
                "question": question,
                "narration_payload": narration_payload,
                "facts": facts,
                "error": error,
            },
        )
