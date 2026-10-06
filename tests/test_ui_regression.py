"""WI-060: Automated UI/visual regression tests for the gpo-lens web templates.

Structural assertion tests that catch regressions in template rendering —
no browser, no screenshots. Uses FastAPI's TestClient against the fixture
estate, the same pattern as ``test_danger.py`` and ``test_api.py``.
"""

from __future__ import annotations

import os
import re
import sqlite3
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

try:
    import fastapi  # noqa: F401

    _HAS_WEB = True
except ImportError:
    _HAS_WEB = False

pytestmark = pytest.mark.skipif(
    not _HAS_WEB,
    reason="web extra not installed",
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

# The fixture estate's known GPO IDs (lowercase, braces and hyphens stripped).
_GPO_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # gpo-cpassword
_GPO_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
_GPO_C = "cccccccccccccccccccccccccccccccc"  # version skew
_GPO_E = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"  # loopback
_GPO_DISABLED = "11111111111111111111111111111111"


def _has_class(html: str, cls: str) -> bool:
    """Check that *cls* appears as a whole CSS token, not just a substring.

    ``"gp-table" in html`` would also match ``gp-table-wrap``; this helper
    uses word-boundary matching to avoid that.
    """
    return bool(re.search(rf"\b{re.escape(cls)}\b", html))


# Pages that every authenticated user can reach (VIEW permission).
_PAGES = [
    "/",
    "/briefing",
    "/danger",
    "/findings",
    "/changelog",
    "/baseline",
    "/conflicts",
    "/ask",
    "/ou",
    "/ingest",
    "/resultant",
    "/inventory",
    "/trends",
    "/explore",
    "/tools",
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_fixture_db() -> str:
    from gpo_lens.ingest import load_estate as ingest_load_estate
    from gpo_lens.store import init_db, save_estate

    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        path = f.name
    conn = sqlite3.connect(path)
    init_db(conn)
    estate = ingest_load_estate(FIXTURE_DIR)
    save_estate(conn, estate)
    conn.close()
    return path


@pytest.fixture()
def _fixture_db():
    path = _make_fixture_db()
    try:
        yield path
    finally:
        os.unlink(path)


@pytest.fixture()
def _client(_fixture_db, monkeypatch):
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    app = create_app(_fixture_db)
    return TestClient(
        app,
        headers={
            "origin": "http://localhost",
            "Authorization": "Bearer test-secret-token",
        },
    )


@pytest.fixture()
def _empty_db():
    """A DB with the schema initialised but no snapshots (no estate loaded)."""
    from gpo_lens.store import init_db

    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        path = f.name
    conn = sqlite3.connect(path)
    init_db(conn)
    conn.close()
    try:
        yield path
    finally:
        os.unlink(path)


@pytest.fixture()
def _empty_client(_empty_db, monkeypatch):
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    app = create_app(_empty_db)
    return TestClient(
        app,
        headers={
            "origin": "http://localhost",
            "Authorization": "Bearer test-secret-token",
        },
    )


# ---------------------------------------------------------------------------
# A. Page availability
# ---------------------------------------------------------------------------


class TestPageAvailability:
    """Every page returns 200 and has the expected title."""

    @pytest.mark.parametrize(
        "path,expected_title",
        [
            ("/", "gpo-lens —"),
            ("/danger", "gpo-lens — Dangerous configurations"),
            ("/findings", "gpo-lens — Findings"),
            ("/changelog", "Changelog"),
            ("/baseline", "Baseline"),
            ("/conflicts", "Conflicts"),
            ("/ask", "Ask"),
            ("/ou", "Directory"),
            ("/ingest", "Ingest"),
            ("/resultant", "Principal Resultant"),
            ("/inventory", "Inventory"),
            ("/trends", "Trends"),
        ],
    )
    def test_page_returns_200_and_title(self, _client, path, expected_title) -> None:
        resp = _client.get(path)
        assert resp.status_code == 200, f"{path} returned {resp.status_code}"
        html = resp.text
        assert "<title>" in html
        assert expected_title in html, f"{path}: expected title containing '{expected_title}'"

    def test_dashboard_title_has_domain(self, _client) -> None:
        # The fixture estate has domain "fakefixture.local".
        resp = _client.get("/")
        assert "<title>gpo-lens — fakefixture.local</title>" in resp.text

    def test_gpo_detail_title_has_name(self, _client) -> None:
        resp = _client.get(f"/gpo/{_GPO_A}")
        assert resp.status_code == 200
        assert "<title>gpo-lens — gpo-cpassword</title>" in resp.text

    @pytest.mark.parametrize("path", _PAGES)
    def test_page_content_type_is_html(self, _client, path) -> None:
        resp = _client.get(path)
        assert resp.status_code == 200
        ct = resp.headers.get("content-type", "")
        assert "text/html" in ct, f"{path}: content-type={ct}"


# ---------------------------------------------------------------------------
# B. Navigation structure
# ---------------------------------------------------------------------------


class TestNavigationStructure:
    """The base template renders the same nav scaffold on every page."""

    _NAV_LINKS = [
        ("Briefing", "/briefing"),
        ("Findings", "/findings"),
        ("Explore", "/explore"),
        ("History", "/changelog"),
        ("Tools", "/tools"),
    ]

    @pytest.mark.parametrize("path", _PAGES)
    def test_every_page_has_nav(self, _client, path) -> None:
        html = _client.get(path).text
        assert '<nav class="gp-nav"' in html, f"{path}: missing <nav>"

    @pytest.mark.parametrize("path", _PAGES)
    def test_every_page_has_head_with_title_and_css(self, _client, path) -> None:
        html = _client.get(path).text
        assert "<head>" in html
        assert "<title>" in html
        assert "</title>" in html
        assert 'rel="stylesheet"' in html
        assert "tokens.css" in html

    @pytest.mark.parametrize("path", _PAGES)
    def test_every_page_has_body_with_gp_prefix(self, _client, path) -> None:
        html = _client.get(path).text
        assert "<body>" in html
        assert 'class="gp-app"' in html

    @pytest.mark.parametrize("path", _PAGES)
    def test_nav_contains_all_section_links(self, _client, path) -> None:
        html = _client.get(path).text
        for label, href in self._NAV_LINKS:
            assert f">{label}<" in html, f"{path}: nav missing link text '{label}'"

    @pytest.mark.parametrize("path", _PAGES)
    def test_no_traceback_in_output(self, _client, path) -> None:
        resp = _client.get(path)
        assert resp.status_code != 500, f"{path} returned 500"
        html = resp.text
        assert "Traceback (most recent call last)" not in html, (
            f"{path}: Python traceback leaked into HTML"
        )

    @pytest.mark.parametrize("path", _PAGES)
    def test_no_internal_server_error_text(self, _client, path) -> None:
        resp = _client.get(path)
        assert resp.status_code != 500, f"{path} returned 500"
        html = resp.text
        assert "Internal Server Error" not in html, f"{path}: 'Internal Server Error' text present"

    @pytest.mark.parametrize("path", _PAGES)
    def test_favicon_link_present(self, _client, path) -> None:
        html = _client.get(path).text
        assert 'rel="icon"' in html
        assert "favicon.svg" in html


class TestFindingsInboxIntegration:
    """The lifecycle-backed inbox remains usable as the primary findings UI."""

    @staticmethod
    def _store_findings(db_path: str, findings: list[SimpleNamespace]) -> list[int]:
        """Seed findings through the Plan 024 engine — the deployed path.

        Plan 025 WI-1 moved the inbox onto ``finding_inbox``, which by design
        (WI-1.4) only returns occurrences carrying evaluation-run provenance.
        The legacy ``update_finding_lifecycle`` writer leaves
        ``first_seen_run_id`` NULL, so seeding through it would populate a table
        the page can no longer see — the tests would pass against a store no
        real ingest can produce. ``create_evaluation_run`` + ``run_evaluation``
        is what both the CLI and the web uploader actually run.
        """
        from gpo_lens.finding_model import EvidenceRef, FindingCandidate
        from gpo_lens.findings import (
            create_evaluation_run,
            finding_inbox,
            run_evaluation,
        )
        from gpo_lens.store import list_snapshots

        conn = sqlite3.connect(db_path)
        try:
            snapshot_id = list_snapshots(conn)[0][0]
            candidates = [
                FindingCandidate(
                    detector_id=finding.category,
                    detector_version="1",
                    category=finding.category,
                    severity=finding.severity,
                    subject_type="gpo",
                    subject_key=(finding.gpo_id,),
                    # Distinguish same-category findings on the same GPO, which
                    # would otherwise share a fingerprint and fold into one
                    # occurrence — the pagination test seeds 12 of them.
                    dimensions=(("summary", finding.summary),),
                    summary=finding.summary,
                    detail=finding.detail,
                    evidence_refs=(
                        EvidenceRef(
                            snapshot_id=snapshot_id,
                            gpo_id=finding.gpo_id,
                            source="test",
                            field_path="test",
                            safe_projection="safe text",
                        ),
                    ),
                    gpo_name=finding.gpo_name,
                )
                for finding in findings
            ]
            run_id = create_evaluation_run(conn, snapshot_id)
            run_evaluation(conn, run_id, candidates)
            return [view.occurrence_id for view in finding_inbox(conn, limit=1000)]
        finally:
            conn.close()

    def test_inbox_reads_stored_findings_without_rerunning_detectors(
        self, _client, _fixture_db, monkeypatch
    ) -> None:
        finding = SimpleNamespace(
            category="stored-rule",
            gpo_id=_GPO_A,
            gpo_name="gpo-cpassword",
            severity="high",
            summary="Stored lifecycle finding",
            detail="evidence",
        )
        self._store_findings(_fixture_db, [finding])

        def fail(*_args, **_kwargs):
            raise AssertionError("read path must not rerun whole-estate detectors")

        monkeypatch.setattr("gpo_lens.danger.danger_findings", fail)
        monkeypatch.setattr("gpo_lens.queries.estate_doctor", fail)
        response = _client.get("/findings")
        assert response.status_code == 200
        assert "Stored lifecycle finding" in response.text
        assert "Review" in response.text
        assert 'name="note"' in response.text

    def test_inbox_pagination_uses_filters_and_valid_macro(self, _client, _fixture_db) -> None:
        findings = [
            SimpleNamespace(
                category="page-rule",
                gpo_id=_GPO_A,
                gpo_name="gpo-cpassword",
                severity="medium",
                summary=f"Finding {index}",
                detail=f"evidence-{index}",
            )
            for index in range(12)
        ]
        self._store_findings(_fixture_db, findings)
        response = _client.get("/findings?severity=medium&per_page=5")
        assert response.status_code == 200
        assert 'aria-label="Pagination"' in response.text
        assert "severity=medium" in response.text

    def test_triage_note_and_filter_context_survive_round_trip(self, _client, _fixture_db) -> None:
        finding = SimpleNamespace(
            category="review-rule",
            gpo_id=_GPO_A,
            gpo_name="gpo-cpassword",
            severity="high",
            summary="Needs a decision",
            detail="decision-evidence",
        )
        finding_id = self._store_findings(_fixture_db, [finding])[0]
        response = _client.post(
            f"/findings/{finding_id}/triage",
            data={
                "status": "accepted_risk",
                "note": "Tracked in ticket 42",
                "return_q": "Needs a decision",
                "return_severity": "high",
                "return_category": "review-rule",
                "return_triage": "accepted_risk",
                "return_page": "1",
            },
            follow_redirects=False,
        )
        assert response.status_code == 303
        location = response.headers["location"]
        assert "severity=high" in location
        assert "triage=accepted_risk" in location
        rendered = _client.get(location)
        assert rendered.status_code == 200
        assert "Tracked in ticket 42" in rendered.text
        assert "local-analyst" in rendered.text
        assert "Needs a decision" not in _client.get("/findings").text
        assert "Needs a decision" in _client.get("/findings?lifecycle=all&triage=all").text

    # -- Plan 025 WI-1: the page consumes the Plan 024 core queries ----------

    def _store_multi_run_findings(self, db_path, persisting, regressing):
        """Seed one persisting and one regressed occurrence across three runs."""
        from gpo_lens.finding_model import EvidenceRef, FindingCandidate
        from gpo_lens.findings import create_evaluation_run, run_evaluation
        from gpo_lens.store import list_snapshots

        def candidate(spec):
            return FindingCandidate(
                detector_id=spec.category,
                detector_version="1",
                category=spec.category,
                severity=spec.severity,
                subject_type="gpo",
                subject_key=(spec.gpo_id,),
                summary=spec.summary,
                detail=spec.detail,
                evidence_refs=(
                    EvidenceRef(
                        snapshot_id=1,
                        gpo_id=spec.gpo_id,
                        source="test",
                        field_path="test",
                        safe_projection="safe text",
                    ),
                ),
                gpo_name=spec.gpo_name,
            )

        conn = sqlite3.connect(db_path)
        try:
            snapshot_id = list_snapshots(conn)[0][0]
            both = [candidate(persisting), candidate(regressing)]
            only_persisting = [candidate(persisting)]
            # Present, then absent (resolved), then present again (regressed).
            for cands in (both, only_persisting, both):
                run_id = create_evaluation_run(conn, snapshot_id)
                run_evaluation(conn, run_id, cands)
        finally:
            conn.close()

    def test_default_filter_is_new_or_regressed_open(self, _client, _fixture_db) -> None:
        # Plan 025 WI-1 AC: the default inbox holds exactly the actionable
        # items. A merely-persisting finding is not one; a regression is.
        persisting = SimpleNamespace(
            category="persist-rule",
            gpo_id=_GPO_A,
            gpo_name="gpo-cpassword",
            severity="high",
            summary="Merely persisting",
            detail="persist-evidence",
        )
        regressing = SimpleNamespace(
            category="regress-rule",
            gpo_id=_GPO_B,
            gpo_name="gpo-b",
            severity="high",
            summary="Came back again",
            detail="regress-evidence",
        )
        self._store_multi_run_findings(_fixture_db, persisting, regressing)

        default = _client.get("/findings")
        assert default.status_code == 200
        assert "Came back again" in default.text
        assert "Merely persisting" not in default.text

        # Widening the lifecycle filter reveals it — nothing was deleted.
        widened = _client.get("/findings?lifecycle=all")
        assert "Merely persisting" in widened.text
        assert "Came back again" in widened.text

    def test_filters_are_url_addressable_and_bounded(self, _client, _fixture_db) -> None:
        findings = [
            SimpleNamespace(
                category="page-rule",
                gpo_id=_GPO_A,
                gpo_name="gpo-cpassword",
                severity="medium" if index % 2 else "critical",
                summary=f"Bounded finding {index}",
                detail=f"evidence-{index}",
            )
            for index in range(12)
        ]
        self._store_findings(_fixture_db, findings)

        # The filter is honoured in SQL, so the count reflects the whole
        # matching set rather than whatever survived a pre-filter row cap.
        crit = _client.get("/findings?severity=critical&per_page=2")
        assert crit.status_code == 200
        assert 'aria-label="Pagination"' in crit.text
        assert "severity=critical" in crit.text
        # 6 critical of 12 → 3 pages of 2. The total comes from a SQL COUNT over
        # the same predicate, so it must say 6 (not 12 sliced after the fact).
        assert "6 items" in crit.text
        assert "of 3" in crit.text

        # An out-of-range page clamps to the last page instead of rendering
        # an empty inbox for a bookmarked deep link.
        clamped = _client.get("/findings?severity=critical&per_page=2&page=99")
        assert clamped.status_code == 200
        assert "No findings match the current filters" not in clamped.text

        # An unrecognised filter value widens rather than 400s or empties.
        stale = _client.get("/findings?lifecycle=not-a-state&triage=bogus")
        assert stale.status_code == 200
        assert "Bounded finding" in stale.text

    def test_search_filter_reaches_sql(self, _client, _fixture_db) -> None:
        findings = [
            SimpleNamespace(
                category="search-rule",
                gpo_id=_GPO_A,
                gpo_name="gpo-cpassword",
                severity="high",
                summary=summary,
                detail="search-evidence",
            )
            for summary in ("Distinctive needle here", "Unrelated haystack")
        ]
        self._store_findings(_fixture_db, findings)
        hit = _client.get("/findings?q=distinctive")
        assert hit.status_code == 200
        assert "Distinctive needle here" in hit.text
        assert "Unrelated haystack" not in hit.text

    def test_occurrence_view_shows_observations_and_provenance(self, _client, _fixture_db) -> None:
        finding = SimpleNamespace(
            category="occurrence-rule",
            gpo_id=_GPO_A,
            gpo_name="gpo-cpassword",
            severity="high",
            summary="Traceable finding",
            detail="trace-evidence",
        )
        occurrence_id = self._store_findings(_fixture_db, [finding])[0]

        response = _client.get(f"/findings/{occurrence_id}")
        assert response.status_code == 200
        html = response.text
        assert "Traceable finding" in html
        assert "occurrence-rule" in html
        # Provenance: the run that produced the observation, not just the row.
        assert "Observations" in html
        assert "Detector set" in html
        assert "Triage history" in html
        # The inbox links here, so the page must be reachable by a click.
        assert f"/findings/{occurrence_id}" in _client.get("/findings").text

    def test_occurrence_view_shows_triage_log_append_only(self, _client, _fixture_db) -> None:
        finding = SimpleNamespace(
            category="triaged-rule",
            gpo_id=_GPO_A,
            gpo_name="gpo-cpassword",
            severity="high",
            summary="Decided finding",
            detail="decision-evidence",
        )
        occurrence_id = self._store_findings(_fixture_db, [finding])[0]
        _client.post(
            f"/findings/{occurrence_id}/triage",
            data={"status": "acknowledged", "note": "Seen, deferring"},
            follow_redirects=False,
        )
        _client.post(
            f"/findings/{occurrence_id}/triage",
            data={"status": "accepted_risk", "note": "Tracked in ticket 7"},
            follow_redirects=False,
        )
        html = _client.get(f"/findings/{occurrence_id}").text
        # Both decisions survive — the log is append-only, not last-write-wins.
        assert "Seen, deferring" in html
        assert "Tracked in ticket 7" in html
        assert "acknowledged" in html
        assert "accepted_risk" in html

    def test_occurrence_view_reports_regression_predecessor(self, _client, _fixture_db) -> None:
        persisting = SimpleNamespace(
            category="persist-rule",
            gpo_id=_GPO_A,
            gpo_name="gpo-cpassword",
            severity="high",
            summary="Steady finding",
            detail="steady-evidence",
        )
        regressing = SimpleNamespace(
            category="regress-rule",
            gpo_id=_GPO_B,
            gpo_name="gpo-b",
            severity="high",
            summary="Returned finding",
            detail="return-evidence",
        )
        self._store_multi_run_findings(_fixture_db, persisting, regressing)

        from gpo_lens.findings import finding_inbox

        conn = sqlite3.connect(_fixture_db)
        try:
            regressed = finding_inbox(conn, lifecycle_state="regressed")
        finally:
            conn.close()
        assert len(regressed) == 1
        occurrence_id = regressed[0].occurrence_id

        html = _client.get(f"/findings/{occurrence_id}").text
        assert "Regression" in html
        assert "has reappeared" in html
        # Accepted risk must not silently carry over from the predecessor.
        assert "not inherited" in html

    def test_occurrence_view_404s_for_unknown_id(self, _client, _fixture_db) -> None:
        assert _client.get("/findings/999999").status_code == 404

    def test_dossier_count_uses_lifecycle_inbox(self, _client, _fixture_db) -> None:
        finding = SimpleNamespace(
            category="dossier-rule",
            gpo_id=_GPO_A,
            gpo_name="gpo-cpassword",
            severity="critical",
            summary="Dossier finding",
            detail="dossier-evidence",
        )
        self._store_findings(_fixture_db, [finding])
        response = _client.get(f"/gpo/{_GPO_A}")
        assert response.status_code == 200
        assert "/findings?q=gpo-cpassword" in response.text
        assert "lifecycle=all" in response.text
        assert "triage=all" in response.text
        assert "1 finding" in response.text

    # -- Plan 025 WI-2: the briefing page -----------------------------------

    def test_briefing_renders_deterministic_prose(self, _client, _fixture_db) -> None:
        response = _client.get("/briefing")
        assert response.status_code == 200
        html = response.text
        assert "Do I need to care today?" in html
        assert "Estate vitals" in html
        # The fixture estate has a single snapshot, so the briefing must say so
        # rather than implying a comparison against nothing.
        assert "first snapshot" in html

    def test_briefing_has_no_unlinked_stat_tile(self, _client, _fixture_db) -> None:
        # Plan 025 WI-2 AC: no unlinked stat tile appears. Every tile is an
        # <a href>, so count anchors against tiles.
        html = _client.get("/briefing").text
        tiles = re.findall(r'class="gp-posture-tile[^"]*"', html)
        linked = re.findall(r'<a class="gp-posture-tile[^"]*" href="[^"]+"', html)
        assert tiles, "briefing rendered no vitals at all"
        assert len(linked) == len(tiles)

    def test_briefing_vital_keys_all_have_link_targets(self) -> None:
        # A new vital must not be addable without giving the web layer a
        # destination for it — the tile would otherwise be unlinkable.
        from gpo_lens.briefing import VITAL_KEYS
        from gpo_lens.web.routes.briefing import _VITAL_TARGETS

        assert set(VITAL_KEYS) == set(_VITAL_TARGETS)

    def test_briefing_reports_incomplete_analysis(self, _client, _fixture_db) -> None:
        conn = sqlite3.connect(_fixture_db)
        try:
            from gpo_lens.findings import create_evaluation_run

            snapshot_id = conn.execute("SELECT id FROM snapshot").fetchone()[0]
            run_id = create_evaluation_run(conn, snapshot_id)
            conn.execute(
                "UPDATE evaluation_run SET status = 'failed', "
                "error_summary = 'detector crashed' WHERE id = ?",
                (run_id,),
            )
            conn.commit()
        finally:
            conn.close()

        html = _client.get("/briefing").text
        assert "incomplete analysis" in html
        assert "not a verified comparison" in html

    def test_briefing_404s_for_unknown_snapshot(self, _client, _fixture_db) -> None:
        assert _client.get("/briefing?snapshot=999999").status_code == 404

    def test_briefing_on_empty_db_offers_ingest(self, _empty_db, monkeypatch) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        client = TestClient(
            create_app(_empty_db),
            headers={
                "origin": "http://localhost",
                "Authorization": "Bearer test-secret-token",
            },
        )
        response = client.get("/briefing")
        assert response.status_code == 200
        assert "No snapshot ingested yet" in response.text

    @pytest.mark.parametrize("path", _PAGES)
    def test_security_headers_on_every_page(self, _client, path) -> None:
        resp = _client.get(path)
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        csp = resp.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp


# ---------------------------------------------------------------------------
# C. Dashboard rendering
# ---------------------------------------------------------------------------


class TestDashboardRendering:
    def test_dashboard_has_estate_summary_stats(self, _client) -> None:
        html = _client.get("/").text
        assert _has_class(html, "gp-stat")
        assert "GPOs" in html
        assert "Settings" in html

    def test_dashboard_summary_has_gpo_count(self, _client) -> None:
        html = _client.get("/").text
        # The fixture estate has multiple GPOs.
        assert _has_class(html, "gp-stat-val")

    def test_dashboard_has_doctor_findings_section(self, _client) -> None:
        html = _client.get("/").text
        assert "Doctor findings" in html

    def test_dashboard_has_findings_table(self, _client) -> None:
        html = _client.get("/").text
        assert _has_class(html, "gp-table")
        assert "<thead>" in html
        for col in ("Severity", "GPO", "Finding"):
            assert f">{col}<" in html, f"Missing column: {col}"

    def test_dashboard_has_severity_pills(self, _client) -> None:
        html = _client.get("/").text
        assert _has_class(html, "gp-pill")

    def test_dashboard_has_posture_section(self, _client) -> None:
        html = _client.get("/").text
        assert "Posture" in html
        assert _has_class(html, "gp-posture") or _has_class(html, "gp-allclear")

    def test_dashboard_has_export_csv_link(self, _client) -> None:
        html = _client.get("/").text
        assert "Export CSV" in html
        assert "/export/findings" in html

    def test_dashboard_findings_link_to_gpo_detail(self, _client) -> None:
        html = _client.get("/").text
        assert f"/gpo/{_GPO_A}" in html

    def test_dashboard_has_page_head(self, _client) -> None:
        html = _client.get("/").text
        assert _has_class(html, "gp-page-head")


# ---------------------------------------------------------------------------
# D. Danger page rendering
# ---------------------------------------------------------------------------


class TestDangerPageRendering:
    def test_danger_page_has_findings_cards(self, _client) -> None:
        html = _client.get("/danger").text
        assert _has_class(html, "gp-danger-group")
        assert _has_class(html, "gp-danger-group-head")

    def test_danger_cards_have_expected_info(self, _client) -> None:
        html = _client.get("/danger").text
        # Each card surfaces severity (pill), check title, check_id (code),
        # compliance (badge), citation link, GPO name, and detail.
        assert _has_class(html, "gp-pill")
        assert _has_class(html, "gp-badge")
        assert "<code>" in html
        assert "citation" in html
        assert 'target="_blank"' in html
        assert _has_class(html, "gp-danger-finding")
        assert _has_class(html, "gp-danger-finding-gpo")

    def test_danger_page_has_severity_filter(self, _client) -> None:
        html = _client.get("/danger").text
        assert _has_class(html, "gp-filter-bar")
        assert 'name="severity"' in html
        assert "<select" in html

    def test_danger_page_has_search_input(self, _client) -> None:
        html = _client.get("/danger").text
        assert 'name="q"' in html
        assert 'type="search"' in html

    def test_danger_findings_have_severity_pills(self, _client) -> None:
        html = _client.get("/danger").text
        # The fixture estate has a local_admin_push (high severity) finding.
        assert "gp-pill high" in html

    def test_danger_page_shows_local_admin_push(self, _client) -> None:
        html = _client.get("/danger").text
        assert "local_admin_push" in html

    def test_danger_page_has_compliance_badges(self, _client) -> None:
        html = _client.get("/danger").text
        assert _has_class(html, "gp-badge")

    def test_danger_page_has_citation_links(self, _client) -> None:
        html = _client.get("/danger").text
        assert "citation" in html
        assert 'target="_blank"' in html

    def test_danger_page_has_page_head(self, _client) -> None:
        html = _client.get("/danger").text
        assert _has_class(html, "gp-page-head")

    def test_danger_page_has_remediation_details(self, _client) -> None:
        html = _client.get("/danger").text
        assert "<details" in html
        assert ">Remediation<" in html


# ---------------------------------------------------------------------------
# E. Changelog page rendering
# ---------------------------------------------------------------------------


class TestChangelogPageRendering:
    def test_changelog_has_snapshot_selectors(self, _client) -> None:
        html = _client.get("/changelog").text
        assert 'name="snap_a"' in html
        assert 'name="snap_b"' in html
        assert "<select" in html

    def test_changelog_has_compare_button(self, _client) -> None:
        html = _client.get("/changelog").text
        assert "Compare" in html
        assert 'type="submit"' in html

    def test_changelog_has_page_head(self, _client) -> None:
        html = _client.get("/changelog").text
        assert _has_class(html, "gp-page-head")

    def test_changelog_shows_snapshot_count(self, _client) -> None:
        html = _client.get("/changelog").text
        # The fixture DB has one snapshot; the snapshot dropdown should list it.
        assert "snap_a" in html
        assert "snap_b" in html

    def test_changelog_with_few_snapshots_shows_guidance(self, _client) -> None:
        # The fixture DB has only one snapshot, so the "need at least two"
        # guidance should appear.
        html = _client.get("/changelog").text
        assert "Need at least two snapshots" in html


# ---------------------------------------------------------------------------
# F. GPO detail page rendering
# ---------------------------------------------------------------------------


class TestGpoDetailRendering:
    def test_gpo_detail_shows_gpo_name_in_header(self, _client) -> None:
        resp = _client.get(f"/gpo/{_GPO_A}")
        assert resp.status_code == 200
        html = resp.text
        assert "gpo-cpassword" in html
        assert "<h1>" in html

    def test_gpo_detail_has_metadata_section(self, _client) -> None:
        html = _client.get(f"/gpo/{_GPO_A}").text
        assert "Metadata" in html
        assert "Domain" in html

    def test_gpo_detail_has_versions_section(self, _client) -> None:
        html = _client.get(f"/gpo/{_GPO_A}").text
        assert "Versions" in html
        assert "DS (GPC)" in html
        assert "SYSVOL (GPT)" in html

    def test_gpo_detail_has_settings_section(self, _client) -> None:
        html = _client.get(f"/gpo/{_GPO_A}").text
        assert "Side Settings" in html

    def test_gpo_detail_has_export_json_link(self, _client) -> None:
        html = _client.get(f"/gpo/{_GPO_A}").text
        assert "Export JSON" in html
        assert f"/export/gpo/{_GPO_A}" in html

    def test_gpo_detail_has_breadcrumb(self, _client) -> None:
        html = _client.get(f"/gpo/{_GPO_A}").text
        assert _has_class(html, "gp-breadcrumb")
        assert "aria-current" in html

    def test_gpo_detail_has_scope_caveats(self, _client) -> None:
        html = _client.get(f"/gpo/{_GPO_E}").text
        assert "Scope caveats" in html
        assert "flagged, not simulated" in html

    def test_gpo_detail_version_skew_shows_chip(self, _client) -> None:
        html = _client.get(f"/gpo/{_GPO_C}").text
        assert "SKEW" in html
        assert "gp-chip crit" in html

    def test_gpo_detail_disabled_but_populated_warning(self, _client) -> None:
        html = _client.get(f"/gpo/{_GPO_DISABLED}").text
        assert "Disabled but populated" in html

    def test_gpo_detail_has_enabled_disabled_pills(self, _client) -> None:
        html = _client.get(f"/gpo/{_GPO_A}").text
        assert "Computer enabled" in html or "Computer disabled" in html
        assert "User enabled" in html or "User disabled" in html

    def test_gpo_detail_has_page_head(self, _client) -> None:
        html = _client.get(f"/gpo/{_GPO_A}").text
        assert _has_class(html, "gp-page-head")

    def test_gpo_detail_has_delegation_section_when_present(self, _client) -> None:
        # GPO A has delegation entries in the fixture.
        html = _client.get(f"/gpo/{_GPO_A}").text
        assert "Control: who can change this" in html
        assert "<th>Trustee</th>" in html


# ---------------------------------------------------------------------------
# G. Empty state tests
# ---------------------------------------------------------------------------


class TestEmptyStates:
    """An empty database (no snapshots) must not crash any page."""

    # /ou is excluded — the OU list route does not catch ValueError from
    # load_estate on an empty DB (pre-existing gap). It is tracked separately;
    # the parametrized test below documents the expected behaviour for the
    # pages that DO handle empty estates gracefully.
    _EMPTY_SAFE_PAGES = [
        "/",
        "/danger",
        "/changelog",
        "/baseline",
        "/conflicts",
        "/ask",
        "/ingest",
        "/resultant",
        "/inventory",
        "/trends",
    ]

    @pytest.mark.parametrize("path", _EMPTY_SAFE_PAGES)
    def test_empty_db_page_does_not_500(self, _empty_client, path) -> None:
        resp = _empty_client.get(path)
        assert resp.status_code != 500, f"{path} crashed on empty DB"

    @pytest.mark.xfail(
        reason="OU list route does not catch ValueError on empty DB "
        "(pre-existing gap, not introduced by WI-060)",
        strict=True,
    )
    def test_empty_db_ou_list_known_gap(self, _empty_client) -> None:
        """The /ou route raises ValueError → 500 on an empty DB.

        This is a known pre-existing gap in the OU list route (it calls
        ``load_estate`` without a try/except, unlike the dashboard and
        danger routes). This test documents the gap so it is not silently
        forgotten; when fixed, remove the ``xfail`` marker.
        """
        resp = _empty_client.get("/ou")
        assert resp.status_code == 200

    def test_empty_db_dashboard_shows_no_estate(self, _empty_client) -> None:
        resp = _empty_client.get("/")
        assert resp.status_code == 200
        html = resp.text
        assert "No estate loaded" in html
        assert _has_class(html, "gp-empty")

    def test_empty_db_danger_shows_no_findings(self, _empty_client) -> None:
        resp = _empty_client.get("/danger")
        assert resp.status_code == 200
        html = resp.text
        assert "No dangerous configurations" in html or _has_class(html, "gp-callout")

    def test_empty_db_changelog_does_not_crash(self, _empty_client) -> None:
        resp = _empty_client.get("/changelog")
        assert resp.status_code == 200
        html = resp.text
        assert "Changelog" in html

    def test_empty_db_conflicts_does_not_crash(self, _empty_client) -> None:
        resp = _empty_client.get("/conflicts")
        assert resp.status_code == 200

    def test_empty_db_inventory_does_not_crash(self, _empty_client) -> None:
        resp = _empty_client.get("/inventory")
        assert resp.status_code == 200

    def test_empty_db_api_snapshots_returns_empty_list(self, _empty_client) -> None:
        resp = _empty_client.get("/api/v1/snapshots")
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"snapshots": []}

    def test_empty_db_api_query_returns_400(self, _empty_client) -> None:
        resp = _empty_client.get("/api/v1/query/estate_summary")
        assert resp.status_code == 400
        body = resp.json()
        assert body["status"] == "error"
        assert "detail" in body


# ---------------------------------------------------------------------------
# H. Error page tests
# ---------------------------------------------------------------------------


class TestErrorPages:
    def test_unknown_gpo_id_returns_404(self, _client) -> None:
        resp = _client.get("/gpo/00000000000000000000000000000000")
        assert resp.status_code == 404
        assert "GPO not found" in resp.text

    def test_invalid_gpo_id_format_returns_404(self, _client) -> None:
        resp = _client.get("/gpo/not-a-uuid")
        assert resp.status_code == 404
        assert "Invalid GPO ID" in resp.text

    def test_unknown_ou_path_returns_404(self, _client) -> None:
        resp = _client.get("/ou/dc=nonexistent,dc=local")
        assert resp.status_code == 404
        assert "OU not found" in resp.text

    def test_nonexistent_route_returns_404(self, _client) -> None:
        resp = _client.get("/this-route-does-not-exist")
        assert resp.status_code == 404

    def test_error_page_has_styled_html(self, _client) -> None:
        # Send Accept: text/html so the exception handler renders the HTML
        # error page (not the JSON envelope).
        resp = _client.get(
            "/gpo/00000000000000000000000000000000",
            headers={"accept": "text/html"},
        )
        assert resp.status_code == 404
        html = resp.text
        assert _has_class(html, "gp-error")
        assert "404" in html
        assert "Back to dashboard" in html

    def test_error_page_extends_base(self, _client) -> None:
        resp = _client.get(
            "/gpo/00000000000000000000000000000000",
            headers={"accept": "text/html"},
        )
        html = resp.text
        assert '<nav class="gp-nav"' in html

    def test_api_unknown_query_returns_json_404(self, _client) -> None:
        resp = _client.get("/api/v1/query/nonexistent_query")
        assert resp.status_code == 404
        assert "application/json" in resp.headers.get("content-type", "")
        body = resp.json()
        assert body["status"] == "error"
        assert "detail" in body


# ---------------------------------------------------------------------------
# I. API response structure tests
# ---------------------------------------------------------------------------


class TestApiResponseStructure:
    _API_ENDPOINTS = [
        "/api/v1/",
        "/api/v1/health",
        "/api/v1/queries",
        "/api/v1/snapshots",
        "/api/v1/trends",
    ]

    @pytest.mark.parametrize("path", _API_ENDPOINTS)
    def test_api_returns_json_content_type(self, _client, path) -> None:
        resp = _client.get(path)
        assert resp.status_code == 200
        ct = resp.headers.get("content-type", "")
        assert "application/json" in ct, f"{path}: content-type={ct}"

    @pytest.mark.parametrize("path", _API_ENDPOINTS)
    def test_api_returns_valid_json(self, _client, path) -> None:
        resp = _client.get(path)
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, dict)

    def test_api_root_has_endpoints_list(self, _client) -> None:
        body = _client.get("/api/v1/").json()
        assert "name" in body
        assert "version" in body
        assert "endpoints" in body
        assert isinstance(body["endpoints"], list)

    def test_api_queries_has_query_dict(self, _client) -> None:
        body = _client.get("/api/v1/queries").json()
        assert "queries" in body
        assert isinstance(body["queries"], dict)
        assert len(body["queries"]) > 0

    def test_api_query_success_envelope(self, _client) -> None:
        body = _client.get("/api/v1/query/estate_summary").json()
        assert body["status"] == "ok"
        assert "data" in body
        assert isinstance(body["data"], dict)

    def test_api_snapshots_has_list(self, _client) -> None:
        body = _client.get("/api/v1/snapshots").json()
        assert "snapshots" in body
        assert isinstance(body["snapshots"], list)
        assert len(body["snapshots"]) > 0

    def test_api_health_has_status(self, _client) -> None:
        body = _client.get("/api/v1/health").json()
        assert body["status"] == "ok"
        assert "version" in body

    def test_api_error_responses_have_detail(self, _client) -> None:
        resp = _client.get("/api/v1/query/nonexistent")
        body = resp.json()
        assert body["status"] == "error"
        assert "detail" in body


# ---------------------------------------------------------------------------
# CSS class regression tests
# ---------------------------------------------------------------------------


class TestCssClassRegression:
    """Verify that key CSS classes used by JavaScript or layout are present."""

    def test_dashboard_has_gp_table(self, _client) -> None:
        html = _client.get("/").text
        assert _has_class(html, "gp-table")

    def test_dashboard_has_gp_page_head(self, _client) -> None:
        html = _client.get("/").text
        assert _has_class(html, "gp-page-head")

    def test_dashboard_has_gp_filter_bar(self, _client) -> None:
        html = _client.get("/").text
        assert _has_class(html, "gp-filter-bar")

    def test_dashboard_has_gp_pill(self, _client) -> None:
        html = _client.get("/").text
        assert _has_class(html, "gp-pill")

    def test_dashboard_has_gp_callout(self, _client) -> None:
        # The dashboard renders a gp-callout when the filter matches nothing
        # or when all findings are clear. Trigger the "no findings match"
        # callout by searching for a non-existent string.
        html = _client.get("/?q=zzzznomatch").text
        assert _has_class(html, "gp-callout")

    def test_danger_page_has_gp_badge(self, _client) -> None:
        html = _client.get("/danger").text
        assert _has_class(html, "gp-badge")

    def test_danger_page_has_gp_danger_group(self, _client) -> None:
        html = _client.get("/danger").text
        assert _has_class(html, "gp-danger-group")

    def test_danger_page_has_gp_filter_bar(self, _client) -> None:
        html = _client.get("/danger").text
        assert _has_class(html, "gp-filter-bar")

    def test_gpo_detail_has_gp_table(self, _client) -> None:
        html = _client.get(f"/gpo/{_GPO_A}").text
        assert _has_class(html, "gp-table")

    def test_gpo_detail_has_gp_callout(self, _client) -> None:
        html = _client.get(f"/gpo/{_GPO_A}").text
        assert _has_class(html, "gp-callout")

    def test_gpo_detail_has_gp_breadcrumb(self, _client) -> None:
        html = _client.get(f"/gpo/{_GPO_A}").text
        assert _has_class(html, "gp-breadcrumb")

    def test_gpo_detail_has_gp_page_head(self, _client) -> None:
        html = _client.get(f"/gpo/{_GPO_A}").text
        assert _has_class(html, "gp-page-head")

    def test_changelog_has_gp_page_head(self, _client) -> None:
        html = _client.get("/changelog").text
        assert _has_class(html, "gp-page-head")

    def test_changelog_has_gp_callout(self, _client) -> None:
        html = _client.get("/changelog").text
        assert _has_class(html, "gp-callout")

    def test_conflicts_has_gp_tab(self, _client) -> None:
        html = _client.get("/conflicts").text
        assert _has_class(html, "gp-tab")

    def test_conflicts_has_gp_filter_bar(self, _client) -> None:
        html = _client.get("/conflicts").text
        assert _has_class(html, "gp-filter-bar")

    def test_ou_list_has_gp_table(self, _client) -> None:
        html = _client.get("/ou").text
        assert _has_class(html, "gp-table")

    def test_ou_list_has_gp_filter_bar(self, _client) -> None:
        html = _client.get("/ou").text
        assert _has_class(html, "gp-filter-bar")

    def test_ou_list_has_gp_chip(self, _client) -> None:
        html = _client.get("/ou").text
        assert _has_class(html, "gp-chip")

    def test_ingest_has_drop_zone(self, _client) -> None:
        html = _client.get("/ingest").text
        assert "drop-zone" in html
        assert _has_class(html, "gp-drop")

    def test_ingest_has_confirm_overlay(self, _client) -> None:
        html = _client.get("/ingest").text
        assert "confirm-overlay" in html
        assert 'role="dialog"' in html
        assert "aria-modal" in html

    def test_baseline_has_drop_zone(self, _client) -> None:
        html = _client.get("/baseline").text
        assert "drop-zone" in html
        assert _has_class(html, "gp-drop")

    def test_resultant_has_gp_callout(self, _client) -> None:
        html = _client.get("/resultant").text
        assert _has_class(html, "gp-callout")

    def test_resultant_has_gp_breadcrumb(self, _client) -> None:
        html = _client.get("/resultant").text
        assert _has_class(html, "gp-breadcrumb")


# ---------------------------------------------------------------------------
# Template content assertions
# ---------------------------------------------------------------------------


class TestTemplateContent:
    """Assert that key content is present on each page."""

    def test_dashboard_shows_gpo_count(self, _client) -> None:
        html = _client.get("/").text
        assert "GPOs" in html
        # The fixture estate has multiple GPOs — extract the stat value.
        m = re.search(r'gp-stat-label">GPOs.*?gp-stat-val">(\d+)', html, re.DOTALL)
        assert m, "GPO count stat not found"
        count = int(m.group(1))
        assert count > 0, "GPO count should be > 0 for the fixture estate"

    def test_dashboard_shows_som_count(self, _client) -> None:
        html = _client.get("/").text
        assert "OUs / sites" in html

    def test_danger_page_has_at_least_one_finding(self, _client) -> None:
        html = _client.get("/danger").text
        # The fixture estate has a local_admin_push finding.
        assert "local_admin_push" in html
        assert "gp-pill high" in html

    def test_gpo_detail_has_settings_header(self, _client) -> None:
        html = _client.get(f"/gpo/{_GPO_A}").text
        assert "Side Settings" in html

    def test_changelog_has_snapshot_labels(self, _client) -> None:
        html = _client.get("/changelog").text
        assert "Snapshot" in html or "snap_a" in html
        assert "From (older)" in html
        assert "To (newer)" in html

    def test_ou_list_shows_domain(self, _client) -> None:
        html = _client.get("/ou").text
        assert "fakefixture.local" in html

    def test_conflicts_has_tab_labels(self, _client) -> None:
        html = _client.get("/conflicts").text
        assert "Resolved" in html
        assert "Defined" in html

    def test_ask_page_has_question_input(self, _client) -> None:
        html = _client.get("/ask").text
        assert 'name="question"' in html
        assert 'maxlength="500"' in html

    def test_resultant_has_form_fields(self, _client) -> None:
        html = _client.get("/resultant").text
        assert 'name="principal_sid"' in html
        assert "Compute resultant" in html

    def test_ingest_has_upload_form(self, _client) -> None:
        html = _client.get("/ingest").text
        assert 'enctype="multipart/form-data"' in html
        assert 'name="file"' in html
        assert "upload.js" in html


# ---------------------------------------------------------------------------
# Inventory page (nav link, not in original spec but worth covering)
# ---------------------------------------------------------------------------


class TestInventoryRendering:
    def test_inventory_returns_200(self, _client) -> None:
        resp = _client.get("/inventory")
        assert resp.status_code == 200

    def test_inventory_has_gpo_table(self, _client) -> None:
        html = _client.get("/inventory").text
        assert _has_class(html, "gp-table")

    def test_inventory_has_drill_links(self, _client) -> None:
        html = _client.get("/inventory").text
        assert "/gpo/" in html

    def test_inventory_has_page_head(self, _client) -> None:
        html = _client.get("/inventory").text
        assert _has_class(html, "gp-page-head")

    def test_inventory_has_filter_bar(self, _client) -> None:
        html = _client.get("/inventory").text
        assert _has_class(html, "gp-filter-bar")


# ---------------------------------------------------------------------------
# J. Trends page rendering
# ---------------------------------------------------------------------------


class TestTrendsRendering:
    def test_trends_page_returns_200(self, _client) -> None:
        resp = _client.get("/trends")
        assert resp.status_code == 200

    def test_trends_page_has_title(self, _client) -> None:
        html = _client.get("/trends").text
        assert "<title>" in html
        assert "trends" in html.lower()

    def test_trends_page_has_table(self, _client) -> None:
        html = _client.get("/trends").text
        assert _has_class(html, "gp-table")


# ---------------------------------------------------------------------------
# K. OU detail page rendering
# ---------------------------------------------------------------------------


class TestOuDetailRendering:
    def test_ou_detail_returns_200_and_title(self, _client) -> None:
        # Use a known SOM path from the fixture estate.
        resp = _client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        assert "<title>" in resp.text

    def test_ou_detail_has_gpo_chain_table(self, _client) -> None:
        resp = _client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        html = resp.text
        assert _has_class(html, "gp-table")
        assert "Effective precedence" in html

    def test_ou_detail_has_caveat_summary(self, _client) -> None:
        """WI-9: the caveat callout shows a count summary, not a bullet wall."""
        resp = _client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        html = resp.text
        # The callout should always be present (either with counts or "None detected").
        assert "Scope caveats" in html
        # When caveats exist, the summary chips and details element should appear.
        # When no caveats, the "None detected" message shows instead.
        assert "gp-caveat-summary" in html or "None detected" in html
