from __future__ import annotations

import json
import logging
import os
import sys
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from gpo_lens import store as _store
from gpo_lens.collection_zip import MAX_ARCHIVE_BYTES, MAX_UNCOMPRESSED_BYTES
from gpo_lens.web import _helpers as _h
from gpo_lens.web.auth import Principal, _is_loopback
from gpo_lens.web.rate_limit import RateLimiter, make_rate_limit_middleware

_logger = logging.getLogger(__name__)

_WEB_DIR = Path(__file__).resolve().parent
_MAX_UPLOAD_BYTES = MAX_ARCHIVE_BYTES
_MAX_UNCOMPRESSED_BYTES = MAX_UNCOMPRESSED_BYTES

# Re-exports — backward compatibility.  Tests import these helpers from
# ``gpo_lens.web.app`` (e.g. ``from gpo_lens.web.app import _sanitize_question``).
# They were extracted to ``web/_helpers.py``; we re-bind them here so the old
# import paths keep working.  Using assignment (not ``from … import … as``)
# avoids ruff treating them as unused imports and removing them.
_base_qs = _h.base_qs
_csv_response = _h.csv_response
_csv_sanitize_cell = _h.csv_sanitize_cell
_filter_findings = _h.filter_findings
_filter_soms = _h.filter_soms
_get_ro_conn = _h.get_ro_conn
_get_rw_conn = _h.get_rw_conn
_json_attachment = _h.json_attachment
_paginate = _h.paginate
_parse_pagination = _h.parse_pagination
_sanitize_question = _h.sanitize_question
_setting_label = _h.setting_label
_stream_upload_to_file = _h.stream_upload_to_file

# The names below are defined *in this module* (not re-exported) because tests
# ``patch()`` / ``monkeypatch.setattr()`` them directly on
# ``gpo_lens.web.app`` and the patched value must be visible to code whose
# ``__globals__`` is this module's dict: ``_MAX_UPLOAD_BYTES``,
# ``_MAX_UNCOMPRESSED_BYTES``, ``_audit_logger``,
# ``_audit_log_configured_path``, ``_safe_extract``.

# ------------------------------------------------------------------
# Safe zip extraction — wrapper preserves tests that patch
# ``gpo_lens.web.app._MAX_UNCOMPRESSED_BYTES`` and then call ``_safe_extract``.
# The function reads the constant from *this module's* ``__globals__`` at call
# time, so the patched value is visible.
# ------------------------------------------------------------------


def _safe_extract(zip_path: Path, dest: Path) -> None:
    """Compatibility wrapper; safety policy is shared with CLI ingestion."""
    from gpo_lens.collection_zip import safe_extract

    safe_extract(
        zip_path,
        dest,
        max_archive_bytes=_MAX_UPLOAD_BYTES,
        max_uncompressed_bytes=_MAX_UNCOMPRESSED_BYTES,
    )


# ------------------------------------------------------------------
# Audit logging — best-effort, append-only JSON-lines audit trail for
# privileged operations. A write failure must never break the audited
# operation; it is logged via ``_logger`` and swallowed. The audit log
# is not in the truth path: it records *that* an operator attempted a
# privileged action, nothing more.
#
# Stays in app.py because tests monkeypatch ``_audit_logger`` and
# ``_audit_log_configured_path`` on ``gpo_lens.web.app`` directly.
# ------------------------------------------------------------------

_audit_logger: logging.Logger | None = None
_audit_log_configured_path: Path | None = None
_audit_lock = threading.Lock()


def _audit_log_path(db_path: str) -> Path:
    """Resolve the audit log file path.

    ``GPO_LENS_AUDIT_LOG`` overrides; otherwise the log sits beside the
    estate database (``<db_dir>/audit.log``).
    """
    env = os.environ.get("GPO_LENS_AUDIT_LOG")
    if env:
        return Path(env)
    return Path(db_path).resolve().parent / "audit.log"


def _ensure_audit_logger(db_path: str) -> None:
    """Lazily (re)configure the module-level audit logger for *db_path*.

    Reconfigures when the target path changes (e.g. an env-var override
    flipped between requests, as in tests). All failures are caught and
    logged via ``_logger``; the audit logger is left ``None`` so
    :func:`_audit` becomes a no-op. Guarded by ``_audit_lock`` so
    concurrent first-call or path-change races cannot orphan file handles.
    """
    global _audit_logger, _audit_log_configured_path
    desired = _audit_log_path(db_path)
    if _audit_logger is not None and _audit_log_configured_path == desired:
        return
    with _audit_lock:
        if _audit_logger is not None and _audit_log_configured_path == desired:
            return
        logger = logging.getLogger("gpo_lens.audit")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()
        try:
            desired.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.FileHandler(str(desired), mode="a", encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(handler)
        except OSError as exc:
            _logger.warning("Cannot open audit log at %s: %s", desired, exc)
            _audit_logger = None
            _audit_log_configured_path = None
            return
        _audit_logger = logger
        _audit_log_configured_path = desired


def _audit(
    action: str,
    principal: Principal | None,
    outcome: str,
    detail: str,
    request: Request,
) -> None:
    """Append a JSON-lines audit entry for a privileged operation.

    Best-effort: any failure is swallowed and logged via ``_logger`` so
    the audited operation is never affected.
    """
    db_path = getattr(request.app.state, "db_path", "")
    if isinstance(db_path, str) and db_path:
        _ensure_audit_logger(db_path)
    if _audit_logger is None:
        return
    request_id: str | None = getattr(request.state, "request_id", None)
    entry: dict[str, object] = {
        "ts": datetime.now(UTC).isoformat(),
        "action": action,
        "principal": principal.name if principal else None,
        "outcome": outcome,
        "detail": detail,
        "request_id": request_id,
    }
    try:
        _audit_logger.info(json.dumps(entry, default=str))
    except Exception as exc:
        _logger.warning("Audit log write failed: %s", exc)


class _FileLock:
    """Cross-process file-based lock for serializing ingest operations.

    Uses ``fcntl.flock`` on Unix and ``msvcrt.locking`` on Windows.
    A ``threading.Lock`` provides a fast-path for same-process contention
    (the common case in single-worker IIS or uvicorn deployments).
    """

    def __init__(self, lock_path: str) -> None:
        self._lock_path = lock_path
        self._fd: int | None = None
        self._thread_lock = threading.Lock()
        self._acquired = False

    def acquire(self, *, blocking: bool = False) -> bool:
        if not self._thread_lock.acquire(blocking=blocking):
            return False
        try:
            self._fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        except OSError as exc:
            self._thread_lock.release()
            _logger.warning("Ingest lock file unavailable: %s", exc)
            return False

        try:
            if sys.platform == "win32":
                import msvcrt

                mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
                msvcrt.locking(self._fd, mode, 1)
            else:
                import fcntl

                flags = fcntl.LOCK_EX
                if not blocking:
                    flags |= fcntl.LOCK_NB
                fcntl.flock(self._fd, flags)
            self._acquired = True
            return True
        except BaseException:
            os.close(self._fd)
            self._fd = None
            self._thread_lock.release()
            return False

    def release(self) -> None:
        if not self._acquired or self._fd is None:
            return
        fd = self._fd
        try:
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            os.close(fd)
            self._fd = None
            self._acquired = False
            self._thread_lock.release()


def create_app(db_path: str, *, root_path: str = "", admx_dir: str | None = None) -> FastAPI:
    app = FastAPI(root_path=root_path, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.db_path = db_path
    try:
        stale_days = int(os.environ.get("GPO_LENS_STALE_SNAPSHOT_DAYS", "8"))
        if stale_days <= 0:
            raise ValueError("threshold must be positive")
    except ValueError:
        _logger.warning("Invalid GPO_LENS_STALE_SNAPSHOT_DAYS; using 8 days")
        stale_days = 8
    app.state.stale_snapshot_days = stale_days
    if db_path == ":memory:":
        import tempfile

        lock_path = str(Path(tempfile.gettempdir()) / "gpo-lens-memory.ingest.lock")
    else:
        lock_path = str(Path(db_path).resolve()) + ".ingest.lock"
    app.state.ingest_lock = _FileLock(lock_path)

    admx_path = admx_dir or os.environ.get("GPO_LENS_ADMX_DIR")
    app.state.admx = None
    app.state.admx_notice = ""
    try:
        from gpo_lens.admx_parser import find_admx_dir, parse_admx_dir

        if admx_path and Path(admx_path).is_dir():
            app.state.admx = parse_admx_dir(admx_path)
        else:
            auto = find_admx_dir(Path.cwd())
            if auto is None and db_path != ":memory:":
                auto = find_admx_dir(Path(db_path).resolve().parent)
            if auto is not None:
                app.state.admx = parse_admx_dir(auto)
        if app.state.admx is not None and app.state.admx.skipped_files:
            app.state.admx_notice = (
                f"{len(app.state.admx.skipped_files)} template files could not be read; "
                "ADMX names and coverage may be incomplete. See ADMX Coverage for details."
            )
    except Exception as exc:
        # Templates are optional enrichment and must never prevent startup.
        app.state.admx = None
        app.state.admx_notice = (
            f"ADMX templates could not be loaded ({type(exc).__name__}). "
            "Policy names are unavailable; ADMX coverage may be incomplete."
        )
        _logger.warning("ADMX template loading failed: %s", type(exc).__name__)

    # Ensure the DB file exists and is initialized. A file may exist but be
    # empty (e.g. ``touch gpo-lens.sqlite3``) — init_db is idempotent
    # (CREATE TABLE IF NOT EXISTS), so calling it on a valid DB is a no-op.
    # Skip for ``:memory:`` — each connection gets its own private in-memory DB,
    # so initializing here then closing would destroy it (pre-existing limitation).
    if db_path != ":memory:":
        db_file = Path(db_path)
        conn_init = _get_rw_conn(str(db_file))
        try:
            _store.init_db(conn_init)
        finally:
            conn_init.close()

    from gpo_lens import __version__

    templates = Jinja2Templates(directory=str(_WEB_DIR / "templates"))
    from gpo_lens.web import page_narration
    from gpo_lens.web.navigation import section_for_path

    templates.env.globals["legacy_nav"] = os.environ.get("GPO_LENS_LEGACY_NAV", "").lower() in {
        "1",
        "true",
        "yes",
    }
    templates.env.globals["section_for_path"] = section_for_path
    templates.env.globals["app_version"] = __version__
    templates.env.globals["setting_label"] = _setting_label

    app.mount("/static", StaticFiles(directory=str(_WEB_DIR / "static")), name="static")

    # ------------------------------------------------------------------
    # Middleware (closures — they capture ``templates`` for the error page)
    # ------------------------------------------------------------------

    def _is_localhost_origin(origin: str) -> bool:
        from urllib.parse import urlparse

        parsed = urlparse(origin)
        # Reject non-http(s) schemes — ``data:``, ``javascript:``, ``ftp://``,
        # etc. can carry a localhost hostname but are not browser navigations.
        if parsed.scheme not in ("http", "https"):
            return False
        # `0.0.0.0` is the bind-any wildcard, not a legitimate client Origin —
        # a cross-origin attacker can spoof it, so it must NOT be allow-listed.
        return parsed.hostname in (
            "localhost",
            "127.0.0.1",
            "::1",
            "localhost.localdomain",
        )

    def _same_host_origin(url: str, host_header: str) -> bool:
        """True if *url* (an Origin or Referer) is same-host as the request.

        Behind a TLS-terminating reverse proxy (IIS/HttpPlatformHandler) the
        browser's Origin carries the proxy hostname (e.g. ``https://host:8443``),
        not loopback, so a loopback-only allowlist would reject legitimate
        same-origin POSTs. A POST is treated as same-origin when the Origin/
        Referer host:port matches the request's own ``Host`` header — the
        CSRF-relevant signal, since a cross-host attacker cannot make the
        victim's browser send an Origin whose host matches the target Host.

        Comparison details:
        - The scheme must be http or https (rejecting ``data:``, ``javascript:``,
          ``null``, etc.); it is not compared against the request's own scheme,
          which uvicorn sees as ``http`` even behind TLS termination.
        - Only the host:port (netloc) is compared. A trailing default port
          (``:443`` for https, ``:80`` for http) is stripped from both sides so
          ``Origin: https://h:443`` matches ``Host: h`` — browsers omit default
          ports, but curl/scripts may include them.
        - An empty Origin or Host never matches (empty is not a hostname).
        - uvicorn binds loopback and runs with ``proxy_headers=False``, so the
          Host header reflects the proxy/browser rather than a spoofable
          forwarded hop. This trusts the documented TLS+SNI reverse-proxy
          deployment. The outer Host allow-list independently blocks a
          DNS-rebinding origin from selecting an attacker-controlled authority.
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        default_suffix = ":443" if parsed.scheme == "https" else ":80"
        origin_netloc = (parsed.netloc or "").lower()
        host_netloc = (host_header or "").lower()
        if origin_netloc.endswith(default_suffix):
            origin_netloc = origin_netloc[: -len(default_suffix)]
        if host_netloc.endswith(default_suffix):
            host_netloc = host_netloc[: -len(default_suffix)]
        return bool(origin_netloc) and origin_netloc == host_netloc

    from starlette.exceptions import HTTPException as StarletteHTTPException

    _ERROR_TITLES = {
        401: "Authentication required",
        403: "Forbidden",
        404: "Not found",
        409: "Conflict",
        413: "Upload too large",
    }

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception_handler(  # type: ignore[no-untyped-def]
        request: Request, exc: StarletteHTTPException
    ):
        # API paths always get the JSON error envelope, never an HTML page.
        # Auth failures (401/403) and other HTTP exceptions under /api/v1/ must
        # return {"status": "error", "detail": "..."} per the API spec.
        if request.url.path.startswith("/api/v1/"):
            return JSONResponse(
                {"status": "error", "detail": exc.detail},
                status_code=exc.status_code,
            )
        # Render a styled page for browsers; keep JSON for API/programmatic use.
        if "text/html" in request.headers.get("accept", ""):
            return templates.TemplateResponse(
                request,
                "error.html",
                {
                    "request": request,
                    "status_code": exc.status_code,
                    "title": _ERROR_TITLES.get(exc.status_code, "Error"),
                    "detail": exc.detail,
                },
                status_code=exc.status_code,
            )
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    @app.middleware("http")
    async def _forwarded_proto(request: Request, call_next):  # type: ignore[no-untyped-def]
        # Behind a same-host, TLS-terminating reverse proxy (e.g. IIS), uvicorn
        # runs with proxy_headers disabled so the loopback peer — not a forwarded
        # client IP — drives loopback-trust auth (see cli/_serve.py). That leaves
        # the request scheme as "http", so url_for() would emit http:// links
        # that the https page blocks as mixed content (and nav to the wrong
        # scheme). uvicorn binds 127.0.0.1, so X-Forwarded-Proto can only come
        # from the local proxy; honor it for the scheme only, never the client.
        # Gate on loopback peer so an external attacker cannot inject the
        # header over a direct connection.
        proto = request.headers.get("x-forwarded-proto")
        client_host = request.client.host if request.client else None
        if proto in ("http", "https") and _is_loopback(client_host):
            request.scope["scheme"] = proto
        return await call_next(request)

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        )
        return response

    @app.middleware("http")
    async def _body_size_limit(request: Request, call_next):  # type: ignore[no-untyped-def]
        # Reject oversized POST bodies on form-only routes early, before the
        # ASGI framework buffers the full body. Upload routes (/ingest,
        # /baseline, /golden-diff) accept up to 500 MB and are excluded.
        if request.method == "POST" and not any(
            request.url.path.startswith(p) for p in ("/ingest", "/baseline", "/golden-diff")
        ):
            cl = request.headers.get("content-length")
            if cl:
                try:
                    if int(cl) > 10 * 1024 * 1024:  # 10MB
                        return JSONResponse(
                            {"detail": "Request body too large"},
                            status_code=413,
                        )
                except ValueError:
                    pass
        return await call_next(request)

    @app.middleware("http")
    async def _csrf_check(request: Request, call_next):  # type: ignore[no-untyped-def]
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            origin = request.headers.get("origin", "")
            referer = request.headers.get("referer", "")
            host = request.headers.get("host", "")
            # A POST is same-origin if Origin/Referer is loopback (direct
            # browser access to uvicorn) or matches the request's own Host
            # (reverse-proxy/IIS deployment). Otherwise reject. With neither
            # header, reject — browsers always send one on a same-origin POST.
            if origin:
                ok = _is_localhost_origin(origin) or _same_host_origin(origin, host)
            elif referer:
                ok = _is_localhost_origin(referer) or _same_host_origin(referer, host)
            else:
                ok = False
            if not ok:
                return JSONResponse(
                    {"detail": "CSRF validation failed"},
                    status_code=403,
                )
        return await call_next(request)

    _ask_limiter = RateLimiter(max_requests=10, window_seconds=60)
    _ingest_limiter = RateLimiter(max_requests=3, window_seconds=300)
    _general_limiter = RateLimiter(max_requests=100, window_seconds=60)
    app.state.rate_limit_ask = _ask_limiter
    app.state.rate_limit_ingest = _ingest_limiter
    app.state.rate_limit_general = _general_limiter
    app.middleware("http")(
        make_rate_limit_middleware(
            ask_limiter=_ask_limiter,
            ingest_limiter=_ingest_limiter,
            general_limiter=_general_limiter,
        )
    )

    @app.middleware("http")
    async def _request_id(request: Request, call_next):  # type: ignore[no-untyped-def]
        # Stable per-request id so audit entries correlate with future request
        # logging if added. The Host allow-list runs before this middleware.
        request.state.request_id = uuid.uuid4().hex[:12]
        return await call_next(request)

    # ------------------------------------------------------------------
    # Route registration — one register() call per surface.
    # Route modules are imported inside create_app() (not at module level)
    # to avoid a circular import: route modules import _audit / _safe_extract
    # / _MAX_UPLOAD_BYTES from this module, which must be fully loaded first.
    # ------------------------------------------------------------------
    from gpo_lens.web.routes import (
        admx_coverage as admx_cov,
    )
    from gpo_lens.web.routes import (
        api,
        ask,
        baseline,
        briefing,
        changelog,
        conflicts,
        dashboard,
        delegation,
        explore,
        export,
        findings,
        golden,
        gpo,
        ingest,
        ou,
        resultant,
        search,
        trends,
    )

    dashboard.register(app, templates)
    briefing.register(app, templates)
    gpo.register(app, templates)
    conflicts.register(app, templates)
    search.register(app, templates)
    ou.register(app, templates)
    ingest.register(app, templates)
    ask.register(app, templates)
    changelog.register(app, templates)
    baseline.register(app, templates)
    export.register(app, templates)
    resultant.register(app, templates)
    trends.register(app, templates)
    delegation.register(app, templates)
    admx_cov.register(app, templates)
    golden.register(app, templates)
    findings.register(app, templates)
    explore.register(app, templates)
    api.register(app, templates)
    page_narration.register(app, templates)

    # Starlette's last registered middleware runs first, including before
    # request IDs, authentication, CSRF, redirects and request.url/url_for.
    from gpo_lens.web.allowed_hosts import HostAllowListMiddleware

    app.add_middleware(
        HostAllowListMiddleware, allowed_hosts=os.environ.get("GPO_LENS_ALLOWED_HOSTS")
    )
    return app
