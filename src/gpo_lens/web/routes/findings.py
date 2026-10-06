"""WI-5: Findings inbox — unified findings page with triage annotations.

Replaces danger list / conflicts / delegation / admx-coverage / baseline /
golden as destinations. One inbox, default filter new-or-regressed + open,
facets by category, severity, GPO, lifecycle state, triage state.

Plan 025 WI-1: the page consumes the Plan 024 core queries (``finding_inbox``,
``finding_inbox_count``, ``finding_inbox_categories``) rather than loading every
active finding and filtering in Python. Every filter and the page window run in
SQL, so a filtered page reflects the whole matching set instead of whatever
survived a pre-filter row cap.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, preventing synchronous SQLite from blocking the event loop.
"""

from __future__ import annotations

import sqlite3
from typing import Any
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from gpo_lens.exports import ExportSection, export_context, occurrence_run_ids
from gpo_lens.safe_output import safe_data
from gpo_lens.web._helpers import (
    _MAX_SEARCH_LEN,
    base_qs,
    get_ro_conn,
    get_rw_conn,
    paginate_total,
    parse_pagination,
)
from gpo_lens.web.auth import Permission, Principal, requires
from gpo_lens.web.page_narration import make_action
from gpo_lens.web.routes.export import view_export

_VALID_TRIAGE = {"open", "acknowledged", "accepted_risk"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

# ``all`` means "no lifecycle predicate"; the rest map straight through to
# finding_inbox's lifecycle_state. The default is Plan 025 WI-1's actionable
# set: first appearances plus regressions.
_DEFAULT_LIFECYCLE = "new_or_regressed"
_VALID_LIFECYCLE = {
    "new",
    "persisting",
    "regressed",
    "new_or_regressed",
    # Occurrences with no stable subject. Reachable only if a detector omits
    # its subject_key, so this is normally an empty view — it exists so the
    # rows are findable rather than silently absent from every other filter.
    "snapshot_scoped",
}


def _latest_snapshot_gpo_ids(conn: sqlite3.Connection) -> set[str]:
    """Return GPO ids present in the newest snapshot, or an empty set."""
    return {
        row[0]
        for row in conn.execute(
            """
            SELECT id FROM gpo
            WHERE snapshot_id = (
                SELECT id FROM snapshot ORDER BY id DESC LIMIT 1
            )
            """
        )
    }


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/findings", response_class=HTMLResponse, name="findings_inbox")
    def findings_inbox(
        request: Request,
        format: str = "",
        severity: str = "",
        category: str = "",
        lifecycle: str = _DEFAULT_LIFECYCLE,
        triage: str = "open",
        q: str = "",
        principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> Response:
        from gpo_lens.findings import (
            finding_inbox,
            finding_inbox_categories,
            finding_inbox_count,
            load_triage_status_map,
        )

        # Unknown values fall back to "no predicate" rather than 400ing: these
        # arrive from bookmarked URLs, and a stale filter should widen the view,
        # not break it.
        severities = sorted(
            {part.strip() for part in severity.split(",") if part.strip() in _VALID_SEVERITIES}
        )
        lifecycle_state = lifecycle if lifecycle in _VALID_LIFECYCLE else None
        triage_status = triage if triage in _VALID_TRIAGE else None
        q = (q or "")[:_MAX_SEARCH_LEN]

        page, per_page_int, per_page_raw = parse_pagination(request)

        conn = get_ro_conn(app.state.db_path)
        try:
            conn.execute("BEGIN")
            # One triage fold, shared by the count and the page query, so the
            # two can never disagree about which occurrences are open.
            status_map = load_triage_status_map(conn)
            filters: dict[str, Any] = {
                "lifecycle_state": lifecycle_state,
                "triage_status": triage_status,
                "category_prefix": category or None,
                "severities": severities or None,
                "search": q or None,
                "status_map": status_map,
            }
            filtered_count = finding_inbox_count(conn, **filters)
            categories = finding_inbox_categories(conn)

            # Clamp the page against the real total before querying, so an
            # out-of-range ``page=`` returns the last page instead of nothing.
            page, offset, pag = paginate_total(filtered_count, page, per_page_int, per_page_raw)
            # per_page=all means no window; the query's own limit still caps it.
            views = finding_inbox(
                conn,
                limit=per_page_int if per_page_int > 0 else 10_000,
                offset=offset,
                **filters,
            )
            resolvable_gpo_ids = _latest_snapshot_gpo_ids(conn)
            context = export_context(
                conn,
                run_ids=occurrence_run_ids(conn, (v.occurrence_id for v in views)),
                admx=app.state.admx,
            )
        finally:
            conn.close()

        if format:
            return view_export(
                request,
                principal,
                "Findings",
                (
                    ExportSection("findings", views),
                    ExportSection(
                        "evidence_refs",
                        (
                            {
                                "occurrence_id": v.occurrence_id,
                                "run_id": v.last_seen_run_id,
                                "gpo_id": v.gpo_id,
                                "source": "finding_observation",
                                "redaction": "raw source [REDACTED]",
                            }
                            for v in views
                        ),
                    ),
                    ExportSection(
                        "triage_state",
                        (
                            {
                                "occurrence_id": v.occurrence_id,
                                "state": status_map.get(v.occurrence_id),
                            }
                            for v in views
                        ),
                    ),
                ),
                format=format,
                run_ids=sorted({v.last_seen_run_id for v in views}),
                context=context,
                filters={
                    "severity": severities,
                    "category": category,
                    "lifecycle": lifecycle_state,
                    "triage": triage_status,
                    "q": q,
                    "page": page,
                    "per_page": per_page_raw,
                    "total": filtered_count,
                    "window_limit": per_page_int if per_page_int > 0 else 10_000,
                },
            )

        all_count = sum(count for _, count in categories)

        rows: list[dict[str, Any]] = []
        for view in views:
            ts = status_map.get(view.occurrence_id)
            rows.append(
                {
                    "id": view.occurrence_id,
                    "rule_id": view.category,
                    "severity": view.severity,
                    "summary": view.summary,
                    "detail": view.detail,
                    "remediation": view.remediation,
                    "gpo_id": view.gpo_id,
                    "gpo_name": view.gpo_name,
                    "first_seen_run": view.first_seen_run_id,
                    "last_seen_run": view.last_seen_run_id,
                    "predecessor_id": view.predecessor_id,
                    "claim_level": view.claim_level,
                    "triage_state": view.triage_status,
                    "triage_note": view.triage_note,
                    "triage_actor": view.triage_actor,
                    "triage_timestamp": ts.updated_at.isoformat() if ts else "",
                    "is_new": view.lifecycle_state == "new",
                }
            )

        findings_qs = base_qs(request, "page", "per_page")

        return templates.TemplateResponse(
            request,
            "findings.html",
            {
                "request": request,
                "rows": safe_data(
                    rows, include_audit=principal.has(Permission.TRIAGE), secrets=context.secrets
                ),
                "all_count": all_count,
                "filtered_count": filtered_count,
                "resolvable_gpo_ids": resolvable_gpo_ids,
                "f_severity": severity,
                "f_category": category,
                "f_lifecycle": lifecycle,
                "f_triage": triage,
                "f_q": q,
                "categories": categories,
                "pag": pag,
                "f_base_qs": findings_qs,
                "can_triage": principal.has(Permission.TRIAGE),
            },
        )

    @app.get(
        "/findings/{occurrence_id}",
        response_class=HTMLResponse,
        name="finding_occurrence",
    )
    def finding_occurrence(
        request: Request,
        occurrence_id: int,
        format: str = "",
        principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> Response:
        """Plan 025 WI-1: one occurrence's observations, provenance, and triage.

        Answers "why does this finding say what it says, and has that changed?"
        — the question the inbox row deliberately does not have room for.
        """
        from gpo_lens.findings import (
            finding_history,
            finding_observation_history,
            load_triage_status_map,
        )
        from gpo_lens.store import load_estate

        conn = get_ro_conn(app.state.db_path)
        try:
            conn.execute("BEGIN")
            try:
                history = finding_history(conn, occurrence_id)
            except ValueError:
                return HTMLResponse("Finding not found", status_code=404)
            observations = finding_observation_history(conn, occurrence_id)
            status = load_triage_status_map(conn).get(occurrence_id)
            context = export_context(
                conn,
                snapshot_ids=sorted({o["snapshot_id"] for o in observations}),
                run_ids=sorted({o["run_id"] for o in observations}),
                admx=app.state.admx,
            )

            # A regression's predecessor is the same finding_key in an earlier,
            # resolved interval. Show enough to justify the "regression" label.
            predecessor = None
            if history.occurrence.predecessor_id is not None:
                try:
                    prior = finding_history(conn, history.occurrence.predecessor_id)
                except ValueError:
                    prior = None
                if prior is not None:
                    predecessor = {
                        "id": prior.occurrence.id,
                        "category": prior.occurrence.category,
                        "first_seen_run": prior.occurrence.first_seen_run_id,
                        "resolved_run": prior.occurrence.resolved_run_id,
                    }

            try:
                estate = load_estate(conn)
                gpo_names = {g.id: g.name for g in estate.gpos}
            except ValueError:
                gpo_names = {}
        finally:
            conn.close()

        if format:
            return view_export(
                request,
                principal,
                "Occurrence history",
                (
                    ExportSection("occurrence", (history.occurrence,)),
                    ExportSection("observations", observations),
                    ExportSection(
                        "triage_events",
                        history.triage_events
                        if principal.has(Permission.TRIAGE)
                        else ({"audit": "[REDACTED]"},),
                    ),
                ),
                format=format,
                snapshot_ids=sorted({o["snapshot_id"] for o in observations}),
                run_ids=sorted({o["run_id"] for o in observations}),
                context=context,
                filters={"occurrence_id": occurrence_id},
            )

        # The occurrence row carries no GPO columns; take the subject from the
        # newest observation's evidence, which is where the detector recorded it.
        gpo_id = ""
        for obs in reversed(observations):
            for ref in obs["evidence"]:
                if isinstance(ref, dict) and ref.get("gpo_id"):
                    gpo_id = str(ref["gpo_id"])
                    break
            if gpo_id:
                break

        # Severity and claim can move between runs without the finding's
        # identity changing; surfacing the transitions is the point of the page.
        changes: list[dict[str, Any]] = []
        for prev, curr in zip(observations, observations[1:], strict=False):
            for field in ("severity", "claim_level", "detector_set_digest"):
                if prev[field] != curr[field]:
                    changes.append(
                        {
                            "run_id": curr["run_id"],
                            "field": field,
                            "before": prev[field],
                            "after": curr[field],
                        }
                    )

        return templates.TemplateResponse(
            request,
            "finding_occurrence.html",
            {
                "request": request,
                "narration_payload": make_action(
                    request,
                    principal,
                    "finding_history",
                    list(dict.fromkeys(obs["snapshot_id"] for obs in observations)),
                    {"observations": len(observations), "changes": len(changes)},
                    evaluation_runs=observations,
                ),
                "occ": history.occurrence,
                "observations": safe_data(observations, secrets=context.secrets),
                "triage_events": safe_data(history.triage_events)
                if principal.has(Permission.TRIAGE)
                else [],
                "triage_status": status,
                "predecessor": predecessor,
                "changes": changes,
                "gpo_id": gpo_id,
                "gpo_name": gpo_names.get(gpo_id, gpo_id),
                "gpo_resolvable": gpo_id in gpo_names,
                "can_triage": principal.has(Permission.TRIAGE),
            },
        )

    @app.post("/findings/{finding_id}/triage", response_model=None, name="findings_triage")
    def findings_triage(
        request: Request,
        finding_id: int,
        status: str = Form(...),
        note: str = Form(""),
        return_q: str = Form(""),
        return_severity: str = Form(""),
        return_category: str = Form(""),
        return_lifecycle: str = Form(""),
        return_triage: str = Form(""),
        return_page: str = Form(""),
        principal: Principal = Depends(requires(Permission.TRIAGE)),
    ) -> HTMLResponse | RedirectResponse:
        from gpo_lens.findings import triage_finding

        if status not in _VALID_TRIAGE:
            return HTMLResponse("Invalid triage status", status_code=400)

        conn = get_rw_conn(app.state.db_path)
        try:
            triage_finding(conn, finding_id, status, note, principal.name)
        except sqlite3.IntegrityError:
            return HTMLResponse("Finding not found", status_code=404)
        except ValueError as exc:
            return HTMLResponse(str(exc), status_code=400)
        finally:
            conn.close()

        query = {
            key: value
            for key, value in {
                "q": return_q[:_MAX_SEARCH_LEN],
                "severity": return_severity,
                "category": return_category,
                "lifecycle": return_lifecycle,
                "triage": return_triage,
                "page": return_page if return_page.isdigit() else "",
            }.items()
            if value
        }
        target = str(request.url_for("findings_inbox"))
        if query:
            target = f"{target}?{urlencode(query)}"
        return RedirectResponse(url=target, status_code=303)
