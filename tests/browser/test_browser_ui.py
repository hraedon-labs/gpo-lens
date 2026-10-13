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

import base64
import hashlib
import io
import json
import os
import re
import sys
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
# Run-specific text in axe html snippets (random port origin, ingest timestamps).
_VOLATILE = (
    (re.compile(r"https?://127\.0\.0\.1:\d+"), ""),
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?"), "<ts>"),
)

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
    assert _load_axe_source().startswith(f"/*! axe v{AXE_VERSION}")


def test_tampered_axe_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    tampered = tmp_path / AXE_PATH.name
    tampered.write_bytes(AXE_PATH.read_bytes() + b"\n// tampered")
    monkeypatch.setattr(sys.modules[__name__], "AXE_PATH", tampered)
    with pytest.raises(AssertionError, match="sha256"):
        _load_axe_source()


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
    page.keyboard.press("Enter")
    page.wait_for_url(re.compile(r"/changelog$"))

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
    # triage-form.js posts with fetch and navigates once the decision is saved.
    with page.expect_navigation(url=re.compile(r"/findings(\?|$)")):
        form.get_by_role("button", name="Save decision").click()

    rows = fresh_server.query(events, finding_id)
    assert rows == [("acknowledged", "browser test: synthetic acknowledgement", "local-analyst")]
    _goto(page, fresh_server.url + "/findings?triage=acknowledged")
    row = page.locator("tr", has=page.locator(f'form[action$="/findings/{finding_id}/triage"]'))
    expect(row.locator(".gp-chip", has_text="acknowledged")).to_be_visible()
    assert health.problems == []


def test_refused_note_keeps_the_draft_and_never_echoes_it(
    page: Page, fresh_server: LiveServer
) -> None:
    """A note carrying GPP ciphertext is refused in place: the reason shows in
    the form, the draft stays editable, nothing is stored or echoed."""
    health = PageHealth(page)
    _goto(page, fresh_server.url + "/findings")
    review = page.locator("details.gp-triage").first
    form = review.locator("form.gp-triage-form")
    action = form.get_attribute("action")
    assert action is not None
    finding_id = int(re.search(r"/findings/(\d+)/triage", action).group(1))  # type: ignore[union-attr]
    events = "SELECT action, note, actor FROM finding_triage_event WHERE occurrence_id = ?"
    # Two random AES blocks, base64 without padding: the shape GPP writes.
    secret = base64.b64encode(hashlib.sha256(b"browser-refusal").digest()).decode().rstrip("=")
    draft = f"old local admin cpassword was {secret} - removed"

    review.locator("summary").click()
    form.locator("select[name=status]").select_option("acknowledged")
    note = form.locator("textarea[name=note]")
    note.fill(draft)
    with page.expect_response(re.compile(r"/findings/\d+/triage$")) as refused:
        form.get_by_role("button", name="Save decision").click()
    assert refused.value.status == 400
    assert secret not in refused.value.text()

    error = form.locator(".gp-triage-error")
    expect(error).to_be_visible()
    expect(error).to_contain_text("looks like it contains a Group Policy Preferences cpassword")
    expect(error).to_have_attribute("role", "alert")
    assert secret not in error.inner_text()
    expect(note).to_have_value(draft)
    assert page.url == fresh_server.url + "/findings"
    assert fresh_server.query(events, finding_id) == []

    note.fill("old local admin password removed from Groups.xml")
    with page.expect_navigation(url=re.compile(r"/findings(\?|$)")):
        form.get_by_role("button", name="Save decision").click()
    assert fresh_server.query(events, finding_id) == [
        ("acknowledged", "old local admin password removed from Groups.xml", "local-analyst")
    ]
    # The refused POST is the only problem: its 400 and the browser's report of it.
    assert health.problems, "the refusal should have been observed"
    assert all("400" in problem for problem in health.problems), health.problems


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
    page.locator('main a[href="/ingest"]').click()
    page.wait_for_url(re.compile(r"/ingest$"))

    page.locator("#file-input").set_input_files(archive)
    proceed = page.locator("#confirm-proceed")
    # An existing snapshot triggers the replace confirmation, which takes focus.
    expect(proceed).to_be_focused()
    proceed.click()
    # A successful ingest redirects (303) to the legacy dashboard.
    page.wait_for_url(fresh_server.url + "/")
    page.wait_for_load_state("networkidle")
    snapshots = fresh_server.query("SELECT id FROM snapshot ORDER BY id")
    assert len(snapshots) == fresh_server.snapshots_at_start + 1
    assert health.problems == []


def _load_axe_source() -> str:
    """The vendored axe bytes, refused unless they match the pinned SHA-256."""
    data = AXE_PATH.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != AXE_SHA256:
        raise AssertionError(f"{AXE_PATH.name} sha256 {digest} != pinned {AXE_SHA256}")
    return data.decode("utf-8")


def _axe_violations(page: Page) -> list[dict[str, Any]]:
    page.evaluate(_load_axe_source())
    assert page.evaluate("() => axe.version") == AXE_VERSION
    result: list[dict[str, Any]] = page.evaluate(
        """async () => {
            const r = await axe.run(document, {resultTypes: ['violations']});
            return r.violations.map(v => ({id: v.id, impact: v.impact,
                nodes: v.nodes.map(n => ({target: n.target.join(' '), impact: n.impact,
                                          html: n.html}))}));
        }"""
    )
    return result


def _gated(page_path: str, violations: list[dict[str, Any]]) -> dict[tuple[str, str, str], str]:
    """Gated (serious/critical) violations -> axe's html snippet of the node."""
    found: dict[tuple[str, str, str], str] = {}
    for violation in violations:
        for node in violation["nodes"]:
            if (node["impact"] or violation["impact"]) in GATED_IMPACTS:
                key = (page_path, violation["id"], node["target"])
                # Strip run-specific text so the snippet is deterministic.
                html = " ".join(str(node.get("html") or "").split())
                for pattern, replacement in _VOLATILE:
                    html = pattern.sub(replacement, html)
                found.setdefault(key, html[:240])
    return found


def _load_baseline() -> set[tuple[str, str, str]]:
    data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    assert data["axe_version"] == AXE_VERSION
    entries = set()
    for entry in data["entries"]:
        assert entry["reason"] == BASELINE_REASONS[entry["rule"]], entry
        # The node's html documents opaque selectors such as `:root`.
        assert entry.get("html"), f"baseline entry without an html snippet: {entry}"
        entries.add((entry["page"], entry["rule"], entry["target"]))
    return entries


def test_axe_has_no_new_or_stale_serious_violations(page: Page, live_server: LiveServer) -> None:
    health = PageHealth(page)
    found: dict[tuple[str, str, str], str] = {}
    scanned: list[str] = []
    for path in AXE_PAGES:
        response = _goto(page, live_server.url + path)
        assert response.status == 200, f"{path} returned {response.status}; cannot scan it"
        found |= _gated(path, _axe_violations(page))
        scanned.append(path)
    # Console errors / failed requests on any scanned page (including /ingest).
    assert health.problems == [], health.problems

    if os.environ.get("GPO_LENS_AXE_WRITE_BASELINE") == "1":
        # Refuse to rewrite unless every page loaded with 200 and was scanned,
        # so a broken page cannot silently shrink the baseline.
        assert scanned == AXE_PAGES, f"not every page was scanned: {scanned}"
        unexplained = sorted({rule for _, rule, _ in found} - set(BASELINE_REASONS))
        assert not unexplained, f"add a BASELINE_REASONS entry before baselining {unexplained}"
        entries = [
            {"page": p, "rule": r, "target": t, "html": html, "reason": BASELINE_REASONS[r]}
            for (p, r, t), html in sorted(found.items())
        ]
        BASELINE_PATH.write_text(
            json.dumps({"axe_version": AXE_VERSION, "entries": entries}, indent=2) + "\n",
            encoding="utf-8",
        )

    baseline = _load_baseline()
    new = sorted(set(found) - baseline)
    gone = sorted(baseline - set(found))
    assert not new, f"new serious/critical axe violations (fix them): {new}"
    assert not gone, f"baselined violations no longer occur (remove them from the baseline): {gone}"


def test_live_server_refuses_a_foreign_listener(
    live_server: LiveServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Port TOCTOU: if the chosen port is already served by another (healthy)
    gpo-lens, start() must not attach to it. Force every attempt onto the
    shared server's port; start() must fail rather than return that server."""
    import _live

    foreign_port = int(live_server.url.rsplit(":", 1)[1])
    monkeypatch.setattr(_live, "_free_port", lambda: foreign_port)
    with pytest.raises(RuntimeError, match="could not bind"):
        _live.start(tmp_path)
    # The foreign server is untouched and still the one answering.
    assert live_server.process.poll() is None
