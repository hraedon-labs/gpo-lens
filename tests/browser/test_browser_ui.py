"""Real-browser UI and accessibility checks (Playwright + axe-core).

Complements the TestClient HTML-string tests: here a real Chromium drives the
real ``gpo-lens serve`` process (see conftest.py) with CSP, CSRF and the Host
allow-list active.

axe-core is **vendored** (``vendor/axe-4.13.0.min.js``, MPL-2.0, licence
alongside) rather than installed with npm: it keeps a single Python toolchain
(no Node in CI), works offline, and the exact bytes are pinned here by SHA-256
and checked against the version axe reports at run time. Provenance: npm
``axe-core@4.13.0``, registry integrity
``sha512-UzGt8zg7Ny8djbYMhxl2zuEevVa7r2gJjYY5Lwr1xM7+XU2nd6CkIWFTVcCIbAP63vSz71NaVyyuSk9lHKcy0A==``,
``package/axe.min.js`` copied unmodified.

Accessibility gate: every primary page is scanned with axe's default rule set.
Any **serious** or **critical** violation fails unless it is listed in
``axe-baseline.json`` (page + rule id + target selector + reason). A baselined
violation that no longer occurs also fails, so the baseline can only shrink
deliberately. Moderate/minor results are not gated. To regenerate the baseline
after a deliberate fix, run with ``GPO_LENS_AXE_WRITE_BASELINE=1`` and review
the diff; a rule with no entry in ``BASELINE_REASONS`` cannot be baselined.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import zipfile
from pathlib import Path
from typing import Any

import pytest
from _live import GOLDEN, LiveServer
from playwright.sync_api import ConsoleMessage, Page, Request, Response, expect

_HERE = Path(__file__).resolve().parent
AXE_PATH = _HERE / "vendor" / "axe-4.13.0.min.js"
AXE_VERSION = "4.13.0"
AXE_SHA256 = "c24f097bd2f451d4f933e8bc7d8d539f8672a2ebcb5cc9f9f3eec8ca9470a0c1"
BASELINE_PATH = _HERE / "axe-baseline.json"
GATED_IMPACTS = {"serious", "critical"}

# (link text in the primary nav, path it must load)
PRIMARY_NAV = [
    ("Briefing", "/briefing"),
    ("Findings", "/findings"),
    ("Explore", "/explore"),
    ("History", "/changelog"),
    ("Tools", "/tools"),
]
# The History destination keeps its original Changelog page title.
TITLES = {"/briefing": "Briefing", "/findings": "Findings", "/explore": "Explore"}
TITLES |= {"/changelog": "Changelog", "/tools": "Tools"}
AXE_PAGES = [path for _, path in PRIMARY_NAV] + ["/ingest"]

# Why each baselined rule is not fixed in this change. Changing palette tokens
# or link styling is a visual-design decision for the owner, not a trivial fix.
BASELINE_REASONS = {
    "color-contrast": (
        "Muted/secondary text tokens (version tag, eyebrows, table headers, "
        "descriptions) measure below WCAG AA 4.5:1; fixing means changing the "
        "palette tokens, a visual-design decision deferred to the owner."
    ),
    "link-in-text-block": (
        "Inline links are distinguished from body text by colour only; adding "
        "underlines or a 3:1 contrast change is a visual-design decision deferred "
        "to the owner."
    ),
}


class PageHealth:
    """Collects console errors, uncaught exceptions and failed requests."""

    def __init__(self, page: Page) -> None:
        self.problems: list[str] = []
        page.on("console", self._console)
        page.on("pageerror", lambda exc: self.problems.append(f"pageerror: {exc}"))
        page.on("requestfailed", self._failed)
        page.on("response", self._response)

    def _console(self, message: ConsoleMessage) -> None:
        if message.type in {"error", "warning"}:
            self.problems.append(f"console.{message.type}: {message.text}")

    def _failed(self, request: Request) -> None:
        self.problems.append(f"request failed: {request.url} ({request.failure})")

    def _response(self, response: Response) -> None:
        if response.status >= 400:
            self.problems.append(f"HTTP {response.status}: {response.url}")


def _goto(page: Page, url: str) -> Response:
    response = page.goto(url, wait_until="networkidle")
    assert response is not None
    return response


def test_vendored_axe_is_the_pinned_release() -> None:
    assert hashlib.sha256(AXE_PATH.read_bytes()).hexdigest() == AXE_SHA256
    assert AXE_PATH.read_text(encoding="utf-8").startswith(f"/*! axe v{AXE_VERSION}")


@pytest.mark.parametrize(("label", "path"), PRIMARY_NAV)
def test_primary_pages_load_without_errors(
    page: Page, live_server: LiveServer, label: str, path: str
) -> None:
    health = PageHealth(page)
    response = _goto(page, live_server.url + path)
    assert response.status == 200
    expect(page).to_have_title(f"gpo-lens — {TITLES[path]}")
    current = page.locator('nav[aria-label="Primary"] a[aria-current="page"]')
    expect(current).to_have_text(label)
    assert health.problems == []


def test_primary_nav_is_keyboard_operable(page: Page, live_server: LiveServer) -> None:
    health = PageHealth(page)
    _goto(page, live_server.url + "/briefing")

    def focused() -> dict[str, Any]:
        result: dict[str, Any] = page.evaluate(
            """() => { const e = document.activeElement; const s = getComputedStyle(e);
                       return {text: (e.textContent || '').trim(), href: e.getAttribute('href'),
                               outline: s.outlineStyle, width: parseFloat(s.outlineWidth)}; }"""
        )
        return result

    page.keyboard.press("Tab")
    skip = focused()
    assert skip["text"] == "Skip to main content" and skip["href"] == "#main-content"
    page.keyboard.press("Tab")
    assert focused()["text"].startswith("gpo·lens")
    for label, path in PRIMARY_NAV:
        page.keyboard.press("Tab")
        state = focused()
        assert state["text"] == label
        assert state["href"].endswith(path)
        # A visible focus indicator, not just a focus change.
        assert state["outline"] != "none" and state["width"] >= 1, state

    # Activating a focused nav link with Enter navigates.
    page.keyboard.press("Shift+Tab")  # back to History
    with page.expect_navigation():
        page.keyboard.press("Enter")
    assert page.url.endswith("/changelog")

    # The skip link moves focus to the main landmark.
    _goto(page, live_server.url + "/findings")
    page.keyboard.press("Tab")
    page.keyboard.press("Enter")
    assert page.evaluate("() => document.activeElement.id") == "main-content"
    assert health.problems == []


def test_acknowledge_a_finding_round_trip(page: Page, fresh_server: LiveServer) -> None:
    health = PageHealth(page)
    _goto(page, fresh_server.url + "/findings")
    review = page.locator("details.gp-triage").first
    form = review.locator("form.gp-triage-form")
    action = form.get_attribute("action")
    assert action is not None
    finding_id = int(re.search(r"/findings/(\d+)/triage", action).group(1))  # type: ignore[union-attr]
    events = "SELECT action, note, actor FROM finding_triage_event WHERE occurrence_id = ?"
    assert fresh_server.query(events, finding_id) == []

    review.locator("summary").click()
    form.locator("select[name=status]").select_option("acknowledged")
    form.locator("textarea[name=note]").fill("browser test: synthetic acknowledgement")
    with page.expect_navigation():
        form.get_by_role("button", name="Save decision").click()
    assert re.search(r"/findings(\?|$)", page.url)

    rows = fresh_server.query(events, finding_id)
    assert rows == [("acknowledged", "browser test: synthetic acknowledgement", "local-analyst")]
    _goto(page, fresh_server.url + "/findings?triage=acknowledged")
    row = page.locator("tr", has=page.locator(f'form[action$="/findings/{finding_id}/triage"]'))
    expect(row.locator(".gp-chip", has_text="acknowledged")).to_be_visible()
    assert health.problems == []


def _golden_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(GOLDEN.rglob("*")):
            if path.is_file() and path.suffix != ".py":
                zf.write(path, path.relative_to(GOLDEN).as_posix())
    return buffer.getvalue()


def test_tools_ingest_upload_of_a_collector_zip(
    page: Page, fresh_server: LiveServer, tmp_path: Path
) -> None:
    health = PageHealth(page)
    archive = tmp_path / "golden-collector.zip"
    archive.write_bytes(_golden_zip())
    _goto(page, fresh_server.url + "/tools")
    with page.expect_navigation():
        page.locator('main a[href="/ingest"]').click()
    assert page.url.endswith("/ingest")

    page.locator("#file-input").set_input_files(archive)
    proceed = page.locator("#confirm-proceed")
    # An existing snapshot triggers the replace confirmation, which takes focus.
    expect(proceed).to_be_focused()
    with page.expect_navigation():
        proceed.click()
    page.wait_for_load_state("networkidle")
    snapshots = fresh_server.query("SELECT id FROM snapshot ORDER BY id")
    assert len(snapshots) == fresh_server.snapshots_at_start + 1
    assert health.problems == []


def _axe_violations(page: Page) -> list[dict[str, Any]]:
    page.evaluate(AXE_PATH.read_text(encoding="utf-8"))
    assert page.evaluate("() => axe.version") == AXE_VERSION
    result: list[dict[str, Any]] = page.evaluate(
        """async () => {
            const r = await axe.run(document, {resultTypes: ['violations']});
            return r.violations.map(v => ({id: v.id, impact: v.impact,
                nodes: v.nodes.map(n => ({target: n.target.join(' '), impact: n.impact}))}));
        }"""
    )
    return result


def _gated(page_path: str, violations: list[dict[str, Any]]) -> set[tuple[str, str, str]]:
    found = set()
    for violation in violations:
        for node in violation["nodes"]:
            if (node["impact"] or violation["impact"]) in GATED_IMPACTS:
                found.add((page_path, violation["id"], node["target"]))
    return found


def _load_baseline() -> set[tuple[str, str, str]]:
    data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    assert data["axe_version"] == AXE_VERSION
    entries = set()
    for entry in data["entries"]:
        assert entry["reason"] == BASELINE_REASONS[entry["rule"]], entry
        entries.add((entry["page"], entry["rule"], entry["target"]))
    return entries


def test_axe_has_no_new_or_stale_serious_violations(page: Page, live_server: LiveServer) -> None:
    found: set[tuple[str, str, str]] = set()
    for path in AXE_PAGES:
        _goto(page, live_server.url + path)
        found |= _gated(path, _axe_violations(page))

    if os.environ.get("GPO_LENS_AXE_WRITE_BASELINE") == "1":
        unexplained = sorted({rule for _, rule, _ in found} - set(BASELINE_REASONS))
        assert not unexplained, f"add a BASELINE_REASONS entry before baselining {unexplained}"
        entries = [
            {"page": p, "rule": r, "target": t, "reason": BASELINE_REASONS[r]}
            for p, r, t in sorted(found)
        ]
        BASELINE_PATH.write_text(
            json.dumps({"axe_version": AXE_VERSION, "entries": entries}, indent=2) + "\n",
            encoding="utf-8",
        )

    baseline = _load_baseline()
    new = sorted(found - baseline)
    gone = sorted(baseline - found)
    assert not new, f"new serious/critical axe violations (fix them): {new}"
    assert not gone, f"baselined violations no longer occur (remove them from the baseline): {gone}"
