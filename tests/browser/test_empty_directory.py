"""The Directory is usable before and after the first real CLI import."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from _live import _child_env, start, stop
from playwright.sync_api import Page, expect


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_directory_before_and_after_first_import(page: Page, tmp_path: Path, theme: str) -> None:
    server = start(tmp_path, seed=False)
    errors: list[str] = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    try:
        assert server.snapshots_at_start == 0
        response = page.goto(server.url + "/ou")
        assert response is not None and response.status == 200
        if theme == "light":
            page.locator("#theme-toggle").click()
        expect(page.locator("html")).to_have_attribute("data-theme", theme)
        expect(page.locator(".gp-empty .title")).to_have_text("No estate loaded")
        assert page.request.get(server.url + "/ou/ou=missing,dc=example,dc=com").status == 404
        page.screenshot(path=tmp_path / f"directory-empty-{theme}.png", full_page=True)

        subprocess.run(
            [
                sys.executable,
                "-m",
                "gpo_lens",
                "--db",
                str(server.db),
                "ingest",
                str(server.workdir / "estate"),
            ],
            check=True,
            env=_child_env(server.workdir),
            capture_output=True,
            timeout=120,
        )
        response = page.goto(server.url + "/ou")
        assert response is not None and response.status == 200
        assert server.query("SELECT COUNT(*) FROM snapshot") == [(1,)]
        expect(page.locator(".gp-table tbody tr").first).to_be_visible()
        expect(page.locator(".gp-empty")).to_have_count(0)
        expect(page.locator("html")).to_have_attribute("data-theme", theme)
        page.screenshot(path=tmp_path / f"directory-imported-{theme}.png", full_page=True)
        assert errors == []
    finally:
        stop(server)
