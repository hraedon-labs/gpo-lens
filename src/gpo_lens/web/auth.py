from __future__ import annotations

import hmac
import ipaddress
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum

from fastapi import Depends, Header, HTTPException, Request

from gpo_lens.analyst_text import valid_principal_name


class Permission(Enum):
    VIEW = "view"
    INGEST = "ingest"
    # Triage (acknowledge / accept-risk / reopen a finding) is deliberately
    # NOT Permission.INGEST: annotating a finding must never imply the right
    # to upload or replace estate snapshots, and vice versa (WI-088,
    # Plan 024 §8). Finer-grained triage permissions (comment vs acknowledge
    # vs accept-risk) remain Plan 024 work.
    TRIAGE = "triage"
    NARRATE = "narrate"
    ADMIN = "admin"


ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    "viewer": {Permission.VIEW},
    "triager": {Permission.VIEW, Permission.TRIAGE},
    "operator": {Permission.VIEW, Permission.INGEST, Permission.TRIAGE},
    "admin": {
        Permission.VIEW,
        Permission.INGEST,
        Permission.TRIAGE,
        Permission.NARRATE,
        Permission.ADMIN,
    },
}


@dataclass(frozen=True)
class Principal:
    name: str
    role: str
    permissions: frozenset[Permission]

    def has(self, perm: Permission) -> bool:
        return perm in self.permissions


LOCAL_PRINCIPAL = Principal(
    name="local-analyst",
    role="admin",
    permissions=frozenset(Permission),
)

# The web server refuses to bind to a non-loopback address without an auth
# token (see cli/_serve.py), so "no token configured" implies a single local
# operator on their own machine. That operator gets the full local analyst
# capability set (view + ingest + triage + narrate) — withholding ADMIN keeps
# "admin" meaning "explicitly authenticated via token".
LOOPBACK_PRINCIPAL = Principal(
    name="local-analyst",
    role="local",
    permissions=frozenset(
        {Permission.VIEW, Permission.INGEST, Permission.TRIAGE, Permission.NARRATE}
    ),
)


def _get_auth_token() -> str:
    return os.environ.get("GPO_LENS_AUTH_TOKEN", "")


def _forwarded_user(request: Request) -> str | None:
    """Authenticated username forwarded by a trusted same-host reverse proxy.

    Opt-in via ``GPO_LENS_FORWARDED_USER_HEADER`` (the header name, e.g.
    ``X-Forwarded-User``). Only consulted on the loopback-trust path, so a
    remote client can never mint an identity by setting the header itself —
    the TCP peer must be the same-host proxy documented in ``deploy/iis/``.
    The proxy MUST set/overwrite the header on every request (never pass a
    client-supplied value through); see the IIS README for the URL Rewrite
    wiring. The value only *names* the principal so audit-log entries carry
    the real operator instead of ``local-analyst``; it grants nothing beyond
    the loopback permission set.

    The name is stored (``finding_triage_event.actor``, audit events) and
    logged, so it must be an account name — ``user``, ``user@domain`` or
    ``DOMAIN\\user``, at most 256 characters, with no control or format
    character and no GPP cpassword material
    (:func:`gpo_lens.analyst_text.valid_principal_name`). Anything else is
    refused with 401 (fail closed: a proxy sending something else is
    misconfigured), and the value is never echoed.
    """
    header_name = os.environ.get("GPO_LENS_FORWARDED_USER_HEADER", "")
    if not header_name:
        return None
    raw = request.headers.get(header_name, "")
    # Only outer blanks are trimmed; a control character anywhere is refused
    # by the validation below, never silently stripped.
    cleaned = raw.strip(" \t")
    if not cleaned:
        return None
    if not valid_principal_name(cleaned):
        raise HTTPException(
            status_code=401,
            detail=(
                "The forwarded user name is not an account name (user, user@domain "
                "or DOMAIN\\user, at most 256 characters); check the proxy's "
                "forwarded-user header."
            ),
        )
    return cleaned


def _is_loopback(host: str | None) -> bool:
    if host is None:
        return False
    if host == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    if addr.is_loopback:
        return True
    # IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped.is_loopback
    return False


def get_principal(
    request: Request,
    authorization: str | None = Header(default=None),
) -> Principal:
    auth_token = _get_auth_token()
    # If no token configured, allow loopback only (local dev mode)
    if not auth_token:
        if _is_loopback(request.client.host if request.client else None):
            fwd = _forwarded_user(request)
            if fwd is not None:
                return Principal(
                    name=fwd,
                    role="forwarded",
                    permissions=LOOPBACK_PRINCIPAL.permissions,
                )
            return LOOPBACK_PRINCIPAL
        raise HTTPException(
            status_code=401,
            detail="Unauthorized. Authentication required.",
        )
    # Validate bearer token
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid Authorization scheme")
    if not hmac.compare_digest(token, auth_token):
        raise HTTPException(status_code=401, detail="Invalid token")
    return LOCAL_PRINCIPAL


def requires(permission: Permission) -> Callable[..., Awaitable[Principal]]:
    async def _check(
        principal: Principal = Depends(get_principal),
    ) -> Principal:
        if not principal.has(permission):
            raise HTTPException(status_code=403, detail="Forbidden")
        return principal

    _check._required_permission = permission  # type: ignore[attr-defined]
    return _check
