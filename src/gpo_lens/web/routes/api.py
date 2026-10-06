"""REST API routes — WI-057.

A thin JSON layer over the deterministic ``query_dispatch`` surface. All
endpoints are read-only ``GET`` requests under ``/api/v1/``. The API exposes
the deterministic core only — no LLM/narration calls (the import boundary is
respected: this module never imports ``narration``).

Auth follows the same system as the web UI (``Permission.VIEW``); the health
endpoint is exempt so load balancers / monitoring can poll without credentials.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, preventing synchronous SQLite from blocking the event loop
(Plan 022 WI-1).
"""

from __future__ import annotations

import dataclasses
import logging

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from gpo_lens.display import serialize_result
from gpo_lens.query_dispatch import (
    _PARAM_VALIDATORS,
    _QUERY_DESCRIPTIONS,
    QUERY_OPTIONAL_PARAMS,
    QUERY_REQUIRED_PARAMS,
    VALID_QUERIES,
    dispatch_query,
    validate_params,
)
from gpo_lens.safe_output import safe_data, secret_values
from gpo_lens.web._helpers import get_ro_conn
from gpo_lens.web.auth import Permission, Principal, requires

_logger = logging.getLogger(__name__)

# HTTP query parameters arrive as strings. Queries that require an in-process
# object (currently golden_diff's uploaded Estate) have dedicated web routes
# and must not be advertised as callable through this GET API.
_HTTP_QUERIES = frozenset(
    name
    for name in VALID_QUERIES
    if all(
        _PARAM_VALIDATORS.get(name, {}).get(param) is str
        for param in QUERY_REQUIRED_PARAMS.get(name, [])
    )
)


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/api/v1/", name="api_root")
    def api_root() -> JSONResponse:
        return JSONResponse(
            {
                "name": "gpo-lens API",
                "version": "v1",
                "endpoints": [
                    {
                        "method": "GET",
                        "path": "/api/v1/queries",
                        "description": "List all available queries",
                    },
                    {
                        "method": "GET",
                        "path": "/api/v1/query/{query_name}",
                        "description": "Execute a query",
                    },
                    {
                        "method": "GET",
                        "path": "/api/v1/health",
                        "description": "Health check",
                    },
                    {
                        "method": "GET",
                        "path": "/api/v1/snapshots",
                        "description": "List snapshots",
                    },
                    {
                        "method": "GET",
                        "path": "/api/v1/trends",
                        "description": "Posture-over-time trend metrics",
                    },
                ],
            }
        )

    @app.get("/api/v1/queries", name="api_queries")
    def list_queries(
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> JSONResponse:
        queries: dict[str, dict[str, object]] = {}
        for name in sorted(_HTTP_QUERIES):
            queries[name] = {
                "description": _QUERY_DESCRIPTIONS.get(name, ""),
                "required_params": QUERY_REQUIRED_PARAMS.get(name, []),
                "optional_params": QUERY_OPTIONAL_PARAMS.get(name, []),
            }
        return JSONResponse({"queries": queries})

    @app.get("/api/v1/query/{query_name}", name="api_query")
    def run_query(
        request: Request,
        query_name: str,
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> JSONResponse:
        if query_name not in _HTTP_QUERIES:
            return JSONResponse(
                {"status": "error", "detail": f"Unknown query: {query_name}"},
                status_code=404,
            )

        # Collect ALL query string params — validate_params filters to only
        # the accepted keys (required + optional) and validates their types.
        # This lets optional params like computer_sid/dn/computer_dn for
        # principal_resultant flow through instead of being silently dropped.
        params: dict[str, object] = dict(request.query_params)

        # Reject empty required params early (e.g. ?ou_path=) so the query
        # never dispatches with a blank value that would produce nonsense.
        required = QUERY_REQUIRED_PARAMS.get(query_name, [])
        for req_param in required:
            val = params.get(req_param, "")
            if not val or (isinstance(val, str) and not val.strip()):
                return JSONResponse(
                    {"status": "error", "detail": f"Parameter '{req_param}' must not be empty"},
                    status_code=400,
                )

        # Load estate — ValueError (e.g. "No snapshots found") is a client
        # error (400), not an internal server error.
        try:
            from gpo_lens.store import load_estate

            conn = get_ro_conn(app.state.db_path)
            try:
                estate = load_estate(conn)
            finally:
                conn.close()
        except ValueError as exc:
            return JSONResponse(
                {"status": "error", "detail": str(exc)},
                status_code=400,
            )

        try:
            call_kw = validate_params(query_name, {"estate": estate, **params})
        except ValueError as exc:
            return JSONResponse(
                {"status": "error", "detail": str(exc)},
                status_code=400,
            )

        if "admx" in QUERY_OPTIONAL_PARAMS.get(query_name, []):
            call_kw["admx"] = getattr(request.app.state, "admx", None)

        try:
            query_result: object = dispatch_query(query_name, **call_kw)

            # cpassword values are masked — never surface the raw secret.
            if query_name == "cpassword_scan":
                from gpo_lens.detection import mask_cpassword
                from gpo_lens.queries import CpasswordHit

                hits: list[CpasswordHit] = query_result  # type: ignore[assignment]
                query_result = [
                    dataclasses.replace(
                        hit,
                        cpassword=mask_cpassword(hit.cpassword),
                    )
                    for hit in hits
                ]

            serialized = (
                serialize_result(query_result)
                if query_name == "cpassword_scan"
                else safe_data(query_result, secrets=secret_values(estate.gpos))
            )
        except ValueError as exc:
            return JSONResponse(
                {"status": "error", "detail": str(exc)},
                status_code=400,
            )
        except Exception:
            _logger.exception("API query execution failed: %s", query_name)
            return JSONResponse(
                {"status": "error", "detail": "Internal server error"},
                status_code=500,
            )
        return JSONResponse({"status": "ok", "data": serialized})

    @app.get("/api/v1/health", name="api_health")
    def health() -> JSONResponse:
        # No auth — health checks must run without credentials (load balancers,
        # monitoring). The response leaks no estate data: only the build version.
        from gpo_lens import __version__

        return JSONResponse({"status": "ok", "version": __version__})

    @app.get("/api/v1/snapshots", name="api_snapshots")
    def snapshots(
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> JSONResponse:
        from gpo_lens import store as _store

        conn = get_ro_conn(app.state.db_path)
        try:
            rows = _store.list_snapshots(conn)
        finally:
            conn.close()

        snapshot_list = [
            {
                "id": row[0],
                "domain": row[1],
                "taken_at": row[2].isoformat() if row[2] else None,
            }
            for row in rows
        ]
        return JSONResponse({"snapshots": snapshot_list})

    @app.get("/api/v1/trends", name="api_trends")
    def trends(
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> JSONResponse:
        from gpo_lens.trend import compute_trend

        conn = get_ro_conn(app.state.db_path)
        try:
            points = compute_trend(conn)
        finally:
            conn.close()

        return JSONResponse({"status": "ok", "data": serialize_result(points)})
