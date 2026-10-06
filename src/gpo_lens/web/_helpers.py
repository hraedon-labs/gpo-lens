"""Shared utilities for the web UI.

Extracted from ``app.py`` to keep ``create_app()`` wiring-only. These helpers
are pure / stateless — they do not reference module-level mutable state that
tests patch on ``gpo_lens.web.app``. Functions that *do* reference such state
(``_audit``, ``_safe_extract``, ``_ensure_audit_logger``) remain in
``app.py``.
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

from fastapi import Request, UploadFile
from fastapi.responses import Response, StreamingResponse

from gpo_lens import store as _store
from gpo_lens.model import SEVERITY_ORDER

if TYPE_CHECKING:
    from gpo_lens.model import AdmxResolver, Estate

_MAX_QUESTION_LEN = 500
_MAX_SEARCH_LEN = 200  # WI-033: cap q= on / and /ou to prevent unbounded substring scan

_DEFAULT_PER_PAGE = 50
_MAX_PER_PAGE = 200
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_SORTS = {"severity", "severity_desc", "gpo", "finding"}
_SEVERITY_RANK = SEVERITY_ORDER
_VALID_OU_SORTS = {"name", "links", "type"}
_VALID_OU_TYPES = {"domain", "ou", "site"}
_VALID_GPO_SORTS = {"name", "links", "settings", "modified"}
_VALID_GPO_STATUS = {"linked", "unlinked", "empty", "disabled"}

# Health indicators for the dashboard posture grid, in display order. Each is
# (EstateSummary attribute, human label, severity tone). Tone drives both the
# colour and whether a fired indicator floats to the top of the grid.
_POSTURE_SPEC: list[tuple[str, str, str]] = [
    ("cpassword_hit_count", "cPassword secrets", "crit"),
    ("ms16_072_vulnerable_count", "MS16-072 vulnerable", "crit"),
    ("danger_finding_count", "Dangerous configurations", "crit"),
    ("broken_ref_count", "Broken references", "warn"),
    ("broken_wmi_ref_count", "Broken WMI references", "warn"),
    ("version_skew_count", "Version skew", "warn"),
    ("disabled_but_populated_count", "Disabled but populated", "warn"),
    ("dangling_link_count", "Dangling links", "warn"),
    ("conflict_count", "Setting conflicts", "warn"),
    ("orphaned_wmi_filter_count", "Orphaned WMI filters", "warn"),
    ("unlinked_count", "Unlinked GPOs", "info"),
    ("empty_count", "Empty GPOs", "info"),
    ("enforced_link_count", "Enforced links", "info"),
    ("wmi_filtered_gpo_count", "WMI-filtered GPOs", "info"),
    ("loopback_gpo_count", "Loopback GPOs", "info"),
    ("ilt_gpo_count", "Item-level targeting", "info"),
    ("stale_gpo_count", "Stale GPOs (>2y)", "info"),
]

# Maps a posture indicator to the Doctor-finding category that backs it, so a
# posture card can deep-link into the findings table pre-filtered to its issue.
# A value is matched exactly OR as a prefix (``broken_ref`` -> ``broken_ref:unc``,
# ``danger`` -> ``danger:<check>``). Indicators with no backing finding
# (set conflicts, loopback, WMI-filtered) are intentionally absent — they stay
# non-clickable rather than linking to a guaranteed-empty result.
_POSTURE_CATEGORY: dict[str, str] = {
    "cpassword_hit_count": "cpassword",
    "ms16_072_vulnerable_count": "ms16_072",
    "danger_finding_count": "danger",
    "broken_ref_count": "broken_ref",
    "broken_wmi_ref_count": "broken_wmi_ref",
    "version_skew_count": "version_skew",
    "disabled_but_populated_count": "disabled_but_populated",
    "dangling_link_count": "dangling_link",
    "orphaned_wmi_filter_count": "orphaned_wmi_filter",
    "unlinked_count": "unlinked",
    "empty_count": "empty",
    "enforced_link_count": "enforced_link",
    "ilt_gpo_count": "ilt_gpo",
    "stale_gpo_count": "stale_gpo",
}


async def stream_upload_to_file(file: UploadFile, dest: Path, max_bytes: int) -> bool:
    """Stream upload to disk. Returns True if size limit exceeded."""
    total = 0
    with open(dest, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                # Do not drain remaining bytes — reading at the attacker's
                # pace is a slowloris vector. Return immediately; the
                # connection cleanup is handled by the ASGI server.
                return True
            out.write(chunk)
    return False


def get_ro_conn(db_path: str) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)


def get_rw_conn(db_path: str) -> sqlite3.Connection:
    """Open a read-write connection with foreign keys and tightened permissions."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        _store.restrict_db_permissions(conn)
    except BaseException:
        conn.close()
        raise
    return conn


def get_estate(request: Request) -> Estate:
    """Load the estate from the DB, managing the connection lifecycle."""
    from gpo_lens.store import load_estate

    conn = get_ro_conn(request.app.state.db_path)
    try:
        return load_estate(conn)
    finally:
        conn.close()


def sanitize_question(raw: str) -> str:
    """Strip control characters and truncate user question to limit injection risk."""
    # Remove newlines (delimiter breakout vector), null bytes, and other control chars.
    # Tab (\t) is kept because it cannot break delimiter framing.
    cleaned = "".join(ch for ch in raw if (ord(ch) >= 32 or ch == "\t") and ch not in ("\n", "\r"))
    return cleaned[:_MAX_QUESTION_LEN]


def parse_pagination(
    request: Request, page_key: str = "page", per_key: str = "per_page"
) -> tuple[int, int, str]:
    """Parse ``page``/``per_page`` from query params.

    Returns ``(page, per_page_int, per_page_raw)`` where *per_page_int* is
    ``0`` for ``all`` (no slicing) or ``1.._MAX_PER_PAGE``, and *per_page_raw*
    is the original string for round-tripping in pagination links.
    """
    raw_page = request.query_params.get(page_key, "1")
    raw_per = request.query_params.get(per_key, str(_DEFAULT_PER_PAGE))
    try:
        page = max(1, int(raw_page))
    except (ValueError, TypeError):
        page = 1
    if raw_per.lower() == "all":
        return page, 0, "all"
    try:
        per_page = max(1, min(int(raw_per), _MAX_PER_PAGE))
    except (ValueError, TypeError):
        per_page = _DEFAULT_PER_PAGE
    return page, per_page, str(per_page)


def paginate(
    items: list[Any], page: int, per_page: int, per_page_raw: str
) -> tuple[list[Any], dict[str, Any] | None]:
    """Slice *items* for the requested page.

    Returns ``(page_items, pag)`` where *pag* is ``None`` when everything fits
    on one page (no controls needed), otherwise a dict with pagination
    metadata for the template macro.
    """
    total = len(items)
    if per_page <= 0:
        return items, None
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    page_items = items[start : start + per_page]
    if total_pages <= 1:
        return page_items, None
    return page_items, {
        "page": page,
        "per_page_raw": per_page_raw,
        "total": total,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
    }


def paginate_total(
    total: int, page: int, per_page: int, per_page_raw: str
) -> tuple[int, int, dict[str, Any] | None]:
    """Pagination metadata for a page fetched by SQL ``LIMIT``/``OFFSET``.

    The list-slicing sibling ``paginate`` needs every row in memory to know the
    total. Callers that count in SQL already know it, so this takes the *total*
    and returns ``(clamped_page, offset, pag)`` — the offset to query with and
    the same metadata dict the pagination macro consumes.

    *per_page* of ``0`` means "all": offset ``0`` and no controls.
    """
    if per_page <= 0:
        return 1, 0, None
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    offset = (page - 1) * per_page
    if total_pages <= 1:
        return page, offset, None
    return (
        page,
        offset,
        {
            "page": page,
            "per_page_raw": per_page_raw,
            "total": total,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
        },
    )


def base_qs(request: Request, *strip: str) -> str:
    """Build a URL-encoded query string from current params, excluding *strip*."""
    params = dict(request.query_params)
    for key in strip:
        params.pop(key, None)
    return urlencode(params)


def filter_findings(
    findings: list[Any], severity: str, q: str, sort: str, category: str = ""
) -> list[Any]:
    """Apply category, severity filter, text search, and sort to findings.

    *category* matches a finding's ``category`` exactly or as a ``cat:``-prefix
    (so the "Broken references" posture card catches every ``broken_ref:<type>``),
    letting a posture indicator deep-link into this table.
    """
    result = findings
    if category:
        result = [
            f for f in result if f.category == category or f.category.startswith(category + ":")
        ]
    if severity and severity != "all":
        wanted = {s.strip() for s in severity.split(",") if s.strip()}
        result = [f for f in result if f.severity in wanted]
    q = (q or "")[:_MAX_SEARCH_LEN]
    if q:
        needle = q.lower()
        result = [
            f
            for f in result
            if needle in (f.gpo_name or "").lower() or needle in (f.summary or "").lower()
        ]
    if sort == "gpo":
        result = sorted(
            result,
            key=lambda f: (f.gpo_name.lower(), _SEVERITY_RANK.get(f.severity, 9)),
        )
    elif sort == "finding":
        result = sorted(
            result,
            key=lambda f: (f.summary.lower(), _SEVERITY_RANK.get(f.severity, 9)),
        )
    elif sort == "severity_desc":
        result = sorted(result, key=lambda f: -_SEVERITY_RANK.get(f.severity, 9))
    # "severity" (default) — estate_doctor already sorts by severity ascending
    return result


def filter_soms(soms: list[Any], q: str, type_filter: str, sort: str) -> list[Any]:
    """Apply type filter, text search, and sort to a SOM list.

    Search is a case-insensitive substring match over both ``som.name`` and
    ``som.path`` (the DN). Sort defaults to case-insensitive name order so the
    unfiltered Directory is predictably alphabetical.
    """
    result = soms
    if type_filter and type_filter in _VALID_OU_TYPES:
        result = [s for s in result if s.container_type == type_filter]
    q = (q or "")[:_MAX_SEARCH_LEN]
    if q:
        needle = q.lower()
        result = [
            s
            for s in result
            if needle in (s.name or "").lower() or needle in (s.path or "").lower()
        ]
    if sort == "links":
        result = sorted(result, key=lambda s: (-len(s.links), (s.name or "").lower()))
    elif sort == "type":
        result = sorted(result, key=lambda s: (s.container_type, (s.name or "").lower()))
    else:
        result = sorted(result, key=lambda s: (s.name or "").lower())
    return result


def filter_gpos(gpos: list[Any], q: str, status: str, sort: str) -> list[Any]:
    """Apply a status filter, text search, and sort to the GPO inventory.

    *status* is one of ``linked``/``unlinked``/``empty``/``disabled``. Search is
    a case-insensitive substring over name and GUID. Sort defaults to name so the
    unfiltered inventory is predictably alphabetical (the dashboard's findings
    list, by contrast, sorts by severity and is not a GPO browser).
    """
    result = gpos
    if status == "linked":
        result = [g for g in result if g.links]
    elif status == "unlinked":
        result = [g for g in result if not g.links]
    elif status == "empty":
        result = [g for g in result if not g.settings]
    elif status == "disabled":
        result = [g for g in result if not g.computer_enabled and not g.user_enabled]
    q = (q or "")[:_MAX_SEARCH_LEN]
    if q:
        needle = q.lower()
        result = [
            g for g in result if needle in (g.name or "").lower() or needle in (g.id or "").lower()
        ]
    if sort == "links":
        result = sorted(result, key=lambda g: (-len(g.links), (g.name or "").lower()))
    elif sort == "settings":
        result = sorted(result, key=lambda g: (-len(g.settings), (g.name or "").lower()))
    elif sort == "modified":
        # Most-recent first; GPOs without a timestamp sort last.
        result = sorted(
            result,
            key=lambda g: g.modified.timestamp() if g.modified else float("-inf"),
            reverse=True,
        )
    else:
        result = sorted(result, key=lambda g: (g.name or "").lower())
    return result


def filter_settings(items: list[Any], q: str, cse: str) -> list[Any]:
    """Apply a CSE facet + text search to a settings list (WI-083).

    Works for any row exposing ``cse`` / ``identity`` / ``display_name`` /
    ``display_value`` — both ``EffectiveSetting`` (resultant/OU view) and
    ``Setting`` (GPO detail). *cse* is an exact (case-insensitive) match on the
    CSE; *q* is a case-insensitive substring over identity, name, and value.
    """
    result = items
    if cse:
        cl = cse.lower()
        result = [s for s in result if (s.cse or "").lower() == cl]
    q = (q or "")[:_MAX_SEARCH_LEN]
    if q:
        needle = q.lower()
        result = [
            s
            for s in result
            if needle in (s.identity or "").lower()
            or needle in (s.display_name or "").lower()
            or needle in (s.display_value or "").lower()
        ]
    return result


def cse_facets(items: list[Any]) -> list[tuple[str, int]]:
    """Distinct CSEs present in *items* with counts, sorted by name (WI-083)."""
    counts: dict[str, int] = {}
    for s in items:
        c = s.cse or ""
        if c:
            counts[c] = counts.get(c, 0) + 1
    return sorted(counts.items())


# Characters that make spreadsheet apps (Excel/LibreOffice/Sheets) evaluate a
# CSV cell as a formula. Exported data derives from semi-attacker-controllable
# GPO content (GPO names, registry values, finding detail), so an unsanitized
# export can execute formulas in an analyst's spreadsheet (CSV injection /
# CWE-1236). Prefixing such cells with a single quote forces text interpretation.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_sanitize_cell(value: Any) -> Any:
    """Prefix cells that would trigger spreadsheet formula evaluation."""
    if isinstance(value, str) and value and value[0] in _CSV_FORMULA_PREFIXES:
        return f"'{value}"
    return value


def csv_response(rows: list[list[Any]], header: list[str], filename: str) -> StreamingResponse:
    """Build a streaming CSV attachment from a list of row lists.

    All cells are run through :func:`csv_sanitize_cell` to neutralize CSV
    injection (formula-triggering leading characters).
    """

    def _generate() -> Iterator[str]:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([csv_sanitize_cell(h) for h in header])
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)
        for row in rows:
            writer.writerow([csv_sanitize_cell(c) for c in row])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    return StreamingResponse(
        _generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def json_attachment(payload: object, filename: str) -> Response:
    """Build a JSON attachment response (download, not inline)."""
    body = json.dumps(payload, indent=2, default=str)
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def setting_label(s: object, admx: AdmxResolver | None) -> tuple[str, str]:
    if isinstance(s, Mapping):
        side = s.get("side")
        identity = s.get("identity", "")
        display_name = s.get("display_name", identity) or identity
    else:
        side = getattr(s, "side", None)
        identity = getattr(s, "identity", "")
        display_name = getattr(s, "display_name", identity) or identity
    if admx is not None:
        name = admx.resolve_display_name(identity, side=side)
        if name:
            return name, identity
    return display_name, identity
