"""Real-browser fixtures: a live ``gpo-lens serve`` on a free loopback port.

The server is the production entry point (``python -m gpo_lens serve``) run as
a subprocess against a database built by ingesting the synthetic golden estate
through the CLI, so the browser exercises the same middleware stack (Host
allow-list, CSRF, CSP, auth) a local operator gets. No network access is used
beyond 127.0.0.1.

Every test in this directory carries the ``browser`` marker, which the default
``pytest`` run deselects (see ``addopts`` in pyproject.toml). Run them with
``pytest -m browser``.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from _live import LiveServer, start, stop


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    here = Path(__file__).resolve().parent
    for item in items:
        if item.path.resolve().is_relative_to(here):
            item.add_marker(pytest.mark.browser)


@pytest.fixture(scope="session")
def live_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[LiveServer]:
    """Shared read-only server. Tests that mutate state use ``fresh_server``."""
    server = start(tmp_path_factory.mktemp("live"))
    try:
        yield server
    finally:
        stop(server)


@pytest.fixture
def fresh_server(tmp_path: Path) -> Iterator[LiveServer]:
    server = start(tmp_path)
    try:
        yield server
    finally:
        stop(server)


@pytest.fixture
def browser_context_args(
    browser_context_args: dict[str, object], tmp_path_factory: pytest.TempPathFactory
) -> dict[str, object]:
    # CSP is left intact (no bypass_csp): a CSP violation must surface as a
    # console error, which the page-health checks treat as a failure.
    return {**browser_context_args, "viewport": {"width": 1280, "height": 900}}
