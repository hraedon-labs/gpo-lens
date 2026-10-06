"""CLI subcommand for launching the local web UI."""

from __future__ import annotations

import os
import sys
import webbrowser

from gpo_lens.cli._helpers import DEFAULT_DB
from gpo_lens.cli._helpers import _safe_print as print

# Bind-time convenience guard. The canonical per-request loopback check lives
# in gpo_lens.web.auth._is_loopback, which uses ipaddress resolution.
_LOOPBACK_ADDRESSES = {"127.0.0.1", "::1", "localhost"}


def cmd_serve(args: object) -> int:
    import argparse

    a = args if isinstance(args, argparse.Namespace) else argparse.Namespace()
    db = getattr(a, "db", DEFAULT_DB)
    host = getattr(a, "host", "127.0.0.1")
    port = getattr(a, "port", 8000)
    open_browser = getattr(a, "open", False)
    root_path = getattr(a, "root_path", "")
    admx_dir = getattr(a, "admx_dir", None) or os.environ.get("GPO_LENS_ADMX_DIR")

    if host not in _LOOPBACK_ADDRESSES and not os.environ.get("GPO_LENS_AUTH_TOKEN"):
        print(
            "Error: Binding to non-loopback address requires an auth provider "
            "(none configured). Use --host 127.0.0.1 for local access.",
            file=sys.stderr,
        )
        return 1

    try:
        from gpo_lens.web.app import create_app
    except ImportError:
        print("Install the web extra: pip install 'gpo-lens[web]'", file=sys.stderr)
        return 1

    import uvicorn

    app = create_app(db, root_path=root_path, admx_dir=admx_dir)

    if open_browser:
        bracketed = f"[{host}]" if ":" in host else host
        url = f"http://{bracketed}:{port}"
        webbrowser.open(url)

    # Do not trust X-Forwarded-* headers. gpo-lens has no proxy-aware auth; its
    # loopback-trust model assumes the TCP peer is the real client. uvicorn
    # trusts proxy headers from 127.0.0.1 by default, which behind a same-host
    # reverse proxy (e.g. IIS/HttpPlatformHandler) would surface the forwarded
    # client IP and break loopback-trust (every browser request 401s). Treat the
    # same-host proxy as loopback and gate access at the proxy layer instead
    # (see deploy/iis/README.md "Access control").
    uvicorn.run(app, host=host, port=port, proxy_headers=False)
    return 0
