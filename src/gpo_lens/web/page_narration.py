"""Optional narration over the exact, signed deterministic page projection.

The model selects fact IDs, never writes factual prose. This deliberately
narrow fact-check contract makes unsupported entities, findings and claims
unrepresentable. Arbitrary estate strings (including names, values, evidence
and errors) are excluded rather than heuristically scrubbed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from collections.abc import Mapping, Sequence
from typing import Any

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from gpo_lens import __version__
from gpo_lens.query_dispatch import VALID_QUERIES
from gpo_lens.web.auth import Permission, Principal, requires

_MAX_PAYLOAD = 12000
_TTL_SECONDS = 3600
_VIEWS = {
    "dossier",
    "ou",
    "finding_history",
    "gpo_comparison",
    "snapshot_comparison",
    "baseline_comparison",
    "golden_comparison",
}
_VIEWS.update(f"ask:{name}" for name in VALID_QUERIES)
_LABELS = {
    "results": "Deterministic query results returned",
    "settings": "Settings shown",
    "settings_total": "Settings in this scope before filtering",
    "links": "Links recorded",
    "findings": "Open findings recorded",
    "effective_gpos": "GPOs in the OU precedence view",
    "conflicts": "Conflicts recorded",
    "scope_caveats": "Scope caveats recorded",
    "observations": "Persisted observations",
    "changes": "Changes shown",
    "comparisons": "Comparison rows shown",
    "unresolved": "Comparison rows without an ADMX name",
}
_CAVEAT = (
    "These are deterministic page facts. Counts do not establish compliance or "
    "complete collection coverage. OU-level topology flags security filtering, "
    "WMI, loopback, item-level targeting and site links; it does not simulate "
    "per-user or per-machine RSoP."
)


def make_action(
    request: Request,
    principal: Principal,
    view: str,
    snapshot_ids: Sequence[int],
    counts: Mapping[str, int],
    *,
    evaluation_runs: Sequence[Mapping[str, Any]] = (),
) -> str | None:
    """Sign an allowlisted projection built alongside the page's typed result.

    No database re-query and no HTML scrape: callers supply the snapshot IDs
    and counts of the same result passed to their deterministic template.
    """
    if not os.environ.get("GPO_LENS_API_KEY") or not principal.has(Permission.NARRATE):
        return None
    if view not in _VIEWS:
        raise ValueError("Unknown narration view")
    facts = {"scope": _CAVEAT}
    for key, count in counts.items():
        if key not in _LABELS or type(count) is not int or count < 0:
            raise ValueError("Unsafe page fact")
        facts[key] = f"{_LABELS[key]}: {count}."
    # Copy only numeric identifiers from stored evaluation provenance. The run
    # IDs resolve the exact rule/comparator/application provenance on the page;
    # no arbitrary persisted string or evidence is sent to the endpoint.
    runs = [
        {
            key: row[key]
            for key in ("run_id", "snapshot_id", "comparator_input_id")
            if type(row.get(key)) is int
        }
        for row in evaluation_runs[:64]
    ]
    payload = {
        "schema_version": 1,
        "application_version": __version__,
        "analysis": view,
        "snapshot_ids": list(snapshot_ids[:64]),
        "evaluation_runs": runs,
        "provenance_truncated": len(snapshot_ids) > 64 or len(evaluation_runs) > 64,
        "analysis_basis": "persisted evaluation observations"
        if runs
        else "deterministic page computation; no persisted evaluation run claimed",
        "facts": facts,
        "expires_at": int(time.time()) + _TTL_SECONDS,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > _MAX_PAYLOAD:
        return None
    encoded = base64.urlsafe_b64encode(raw).decode()
    digest = hmac.new(
        request.app.state.page_narration_key, encoded.encode(), hashlib.sha256
    ).hexdigest()
    return encoded + "." + digest


def read_payload(token: str, key: bytes) -> dict[str, Any]:
    """Reject changes, expired forms and excessive inputs before any model call."""
    if len(token) > _MAX_PAYLOAD * 2:
        raise ValueError("Payload too large")
    encoded, supplied = token.rsplit(".", 1)
    expected = hmac.new(key, encoded.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, supplied):
        raise ValueError("Invalid signature")
    raw = base64.b64decode(encoded, altchars=b"-_", validate=True)
    if len(raw) > _MAX_PAYLOAD:
        raise ValueError("Payload too large")
    payload: dict[str, Any] = json.loads(raw)
    if payload["expires_at"] < time.time():
        raise ValueError("Expired payload")
    return payload


def fact_check(reply: str, payload: Mapping[str, Any]) -> list[str]:
    """Only IDs in this payload are valid; free text and extra claims fail closed."""
    if len(reply) > _MAX_PAYLOAD:
        raise ValueError("Reply too large")
    selection = json.loads(reply)
    if not isinstance(selection, dict) or set(selection) != {"fact_ids"}:
        raise ValueError("Unsupported claims")
    ids = selection["fact_ids"]
    facts = payload["facts"]
    if not isinstance(ids, list) or not ids or len(ids) > len(facts):
        raise ValueError("Invalid fact selection")
    if any(not isinstance(key, str) or key not in facts for key in ids):
        raise ValueError("Unsupported fact")
    # Scope caveats must survive the model's choice of emphasis/order.
    return [facts["scope"], *(facts[key] for key in dict.fromkeys(ids) if key != "scope")]


def register(app: FastAPI, templates: Jinja2Templates) -> None:
    app.state.page_narration_key = os.urandom(32)

    @app.post("/explain", response_class=HTMLResponse, name="explain_facts")
    def explain_facts(
        request: Request,
        payload: str = Form(..., max_length=_MAX_PAYLOAD * 2),
        principal: Principal = Depends(requires(Permission.NARRATE)),
    ) -> HTMLResponse:
        from gpo_lens.narration import call_llm
        from gpo_lens.web.app import _audit

        try:
            facts = read_payload(payload, app.state.page_narration_key)
        except (ValueError, KeyError, TypeError):
            return templates.TemplateResponse(
                request,
                "narrative_projection.html",
                {
                    "error": (
                        "The page facts expired or changed. "
                        "Reload the deterministic page and try again."
                    )
                },
                status_code=400,
            )
        projection: list[str] = []
        error = None
        if not os.environ.get("GPO_LENS_API_KEY"):
            error = "Narration unavailable. The deterministic page remains authoritative."
        else:
            try:
                reply = call_llm(
                    "Select the most useful facts to explain this page. Return only a JSON object "
                    'with "fact_ids": a nonempty array of IDs from facts. Do not write prose, '
                    "add claims or infer entities, compliance, coverage or RSoP. The supplied "
                    "snapshot and analysis provenance define the entire factual context.",
                    json.dumps(facts),
                    max_tokens=512,
                    timeout=15,
                )
                projection = fact_check(reply, facts)
            except Exception:
                # Do not echo model text, endpoint errors or credentials.
                error = "Narration unavailable. The deterministic page remains authoritative."
        _audit(
            "page_narrate", principal, "error" if error else "success", facts["analysis"], request
        )
        return templates.TemplateResponse(
            request,
            "narrative_projection.html",
            {"projection": projection, "provenance": facts, "error": error},
        )
