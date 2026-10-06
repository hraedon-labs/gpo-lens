"""Validate the HTTP authority before any local trust or URL construction."""

from __future__ import annotations

import ipaddress
import re

from starlette.types import ASGIApp, Receive, Scope, Send

_AUTHORITY = re.compile(r"^(\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*)(?::([0-9]+))?$")
_ENV = "GPO_LENS_ALLOWED_HOSTS"
_LOOPBACK = {"localhost", "127.0.0.1", "[::1]"}


def _authority(value: str) -> tuple[str, int | None] | None:
    match = _AUTHORITY.fullmatch(value)
    if match is None:
        return None
    host, port_text = match.groups()
    host = host.lower()
    if host.startswith("["):
        try:
            host = f"[{ipaddress.IPv6Address(host[1:-1])}]"
        except ipaddress.AddressValueError:
            return None
    # Bound before int conversion (including pathological incoming strings).
    if port_text is not None and (len(port_text) > 5 or not 1 <= int(port_text) <= 65535):
        return None
    return host, int(port_text) if port_text is not None else None


class HostAllowListMiddleware:
    """Outermost ASGI boundary; a bare configured host permits any valid port.

    Explicit host:port entries require that port. No forwarded host is trusted.
    Duplicate, missing and malformed Host headers are always rejected.
    """

    def __init__(self, app: ASGIApp, allowed_hosts: str | None = None) -> None:
        self.app = app
        self.allowed: set[tuple[str, int | None]] = set()
        if allowed_hosts is None:
            self.allowed = {(host, None) for host in _LOOPBACK}
        else:
            for entry in allowed_hosts.split(","):
                parsed = _authority(entry.strip())
                if parsed is None:
                    raise ValueError(f"{_ENV} must contain host or host:port authorities")
                self.allowed.add(parsed)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        hosts = [value for key, value in scope.get("headers", []) if key.lower() == b"host"]
        authority = _authority(hosts[0].decode("latin-1")) if len(hosts) == 1 else None
        if authority is not None and (
            authority in self.allowed or (authority[0], None) in self.allowed
        ):
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        body = f"Host rejected. Configure {_ENV} for this deployment.".encode()
        await send(
            {
                "type": "http.response.start",
                "status": 400,
                "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
