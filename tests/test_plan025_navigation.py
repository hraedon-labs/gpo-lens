"""Plan 025 WI-4: frozen migration inventory, discovery and bookmark contracts."""

import json
from contextlib import closing
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from gpo_lens.web.app import create_app

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-nav-token")
    monkeypatch.delenv("GPO_LENS_LEGACY_NAV", raising=False)
    return TestClient(
        create_app(str(tmp_path / "estate.db")), headers={"Authorization": "Bearer test-nav-token"}
    )


def test_inventory_covers_all_existing_routes(client):
    inventory = json.loads((ROOT / "docs/web-route-inventory.json").read_text())
    covered = {(r["path"], r["name"], tuple(r["methods"])) for r in inventory["routes"]}
    additions = {
        ("/explain", "explain_facts", ("POST",)),
        ("/tools/routes", "route_reference", ("GET",)),
    }
    actual = {
        (r.path, r.name, tuple(sorted(r.methods)) if hasattr(r, "methods") else ("MOUNT",))
        for r in client.app.routes
    }
    assert actual == covered | additions
    for row in inventory["routes"]:
        assert row["destination"] == row["path"]
        assert row["translation"].startswith("identity:")
        client.app.url_path_for(row["discover_via"])


def test_inventory_documents_all_deterministic_export_interfaces(client):
    inventory = json.loads((ROOT / "docs/web-route-inventory.json").read_text())
    rows = {row["name"]: row for row in inventory["routes"]}
    for name in (
        "gpo_detail",
        "findings_inbox",
        "finding_occurrence",
        "briefing",
        "changelog",
        "search",
        "export_findings",
        "export_gpo",
        "accepted_risks",
        "setting_detail",
        "dependencies",
    ):
        row = rows[name]
        query = row.get("representative_export_query", row["representative_query"])
        assert "format=" in query
    for name in ("baseline_post", "golden_diff_post"):
        assert "format=csv|md" in rows[name]["representative_export_form"]
    assert rows["accepted_risks"]["discover_via"] == "findings_inbox"
    assert rows["setting_detail"]["discover_via"] == "search"
    assert 'href="/accepted-risks"' in client.get("/tools").text
    reference = client.get("/tools/routes").text
    assert 'href="/search"' in reference.split("GET /setting")[0].rsplit("<a ", 1)[1]


def test_new_primary_nav_and_accessibility(client):
    page = client.get("/explore").text
    nav = page.split('aria-label="Primary"')[1].split("</nav>")[0]
    for title in ("Briefing", "Findings", "Explore", "History", "Tools"):
        assert f">{title}</a>" in nav
    assert ">Ask</a>" not in nav
    assert ">Inventory</a>" not in nav
    assert 'role="search"' in page
    assert 'name="q"' in page
    assert 'href="#main-content"' in page
    assert '<header class="gp-topbar">' in page
    assert '<main class="gp-page" id="main-content" tabindex="-1">' in page
    css = (ROOT / "src/gpo_lens/web/static/css/tokens.css").read_text()
    assert ":focus-visible" in css and ".gp-skip-link:focus" in css
    assert "@media (max-width: 600px)" in css


def test_reversible_nav(tmp_path, monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-nav-token")
    monkeypatch.setenv("GPO_LENS_LEGACY_NAV", "1")
    client = TestClient(
        create_app(str(tmp_path / "estate.db")), headers={"Authorization": "Bearer test-nav-token"}
    )
    nav = client.get("/tools").text.split('aria-label="Primary"')[1].split("</nav>")[0]
    assert ">Inventory</a>" in nav and ">Dashboard</a>" in nav
    assert ">Ask</a>" not in nav  # narration stays under Tools in either mode
    assert ">Tools</a>" in nav


def test_every_specialist_has_a_visible_directory_home(client):
    pages = "".join(client.get(p).text for p in ("/explore", "/tools", "/tools/routes"))
    inv = json.loads((ROOT / "docs/web-route-inventory.json").read_text())
    for row in inv["routes"]:
        assert row["path"] in pages
        owner = str(client.app.url_path_for(row["discover_via"]))
        assert f'href="{owner}"' in pages


@pytest.mark.parametrize(
    "url",
    [
        "/?severity=high&category=unlinked&q=Lab&sort=gpo",
        "/inventory?q=Lab&status=unlinked&sort=name&page=2",
        "/search?q=Audit&cse=Security&side=Computer",
        "/changelog?snap_a=1&snap_b=2",
        "/findings?category=unlinked&severity=high&lifecycle=all&triage=all&q=Lab&page=2",
    ],
)
def test_old_bookmarks_are_retained_with_query_context(client, url):
    response = client.get(url, follow_redirects=False)
    assert response.status_code == 200
    assert str(response.request.url).endswith(url)
    assert response.context["request"].url.query == url.split("?", 1)[1]
    if url.split("?", 1)[0] not in {"/findings", "/changelog"}:
        assert "Specialist view" in response.text


def test_filter_values_and_snapshot_selection_survive_bookmarks(client):
    from urllib.parse import parse_qs

    urls_and_keys = {
        "/?severity=high&category=unlinked&q=Lab&sort=gpo": {
            "severity": "f_severity",
            "category": "f_category",
            "q": "f_q",
            "sort": "f_sort",
        },
        "/inventory?q=Lab&status=unlinked&sort=name&page=2": {
            "q": "f_q",
            "status": "f_status",
            "sort": "f_sort",
        },
        "/search?q=Audit&cse=Security&side=Computer": {
            "q": "f_q",
            "cse": "f_cse",
            "side": "f_side",
        },
        "/findings?category=unlinked&severity=high&lifecycle=all&triage=all&q=Lab&page=2": {
            "category": "f_category",
            "severity": "f_severity",
            "lifecycle": "f_lifecycle",
            "triage": "f_triage",
            "q": "f_q",
        },
    }
    for url, keys in urls_and_keys.items():
        response = client.get(url)
        expected = parse_qs(url.split("?", 1)[1])
        for query_key, context_key in keys.items():
            assert response.context[context_key] == expected[query_key][0]
    comparison = client.get("/changelog?snap_a=1&snap_b=2")
    assert comparison.context["snap_a"] == 1
    assert comparison.context["snap_b"] == 2


def test_prefixed_deployment_links_and_search_use_root_path(tmp_path, monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-nav-token")
    client = TestClient(
        create_app(str(tmp_path / "estate.db"), root_path="/lens"),
        headers={"Authorization": "Bearer test-nav-token"},
    )
    page = client.get("/explore").text
    assert 'href="/lens/inventory"' in page
    assert 'action="http://testserver/lens/search"' in page
    assert 'href="http://testserver/lens/briefing"' in page


def test_collection_coverage_tile_opens_filtered_findings(client):
    import sqlite3

    from gpo_lens.findings import evaluate_finding_lifecycle_v2
    from gpo_lens.ingest import load_estate
    from gpo_lens.store import save_estate

    with closing(sqlite3.connect(client.app.state.db_path)) as conn, conn:
        estate = load_estate(ROOT / "tests/fixtures")
        sid = save_estate(conn, estate)
        evaluate_finding_lifecycle_v2(conn, sid, estate)
    page = client.get("/briefing")
    target = next(t["href"] for t in page.context["tiles"] if t["label"] == "Coverage gaps")
    assert "/findings?" in target
    assert "category=coverage_gap" in target
    assert "triage=all" in target
    response = client.get(target)
    assert response.status_code == 200
    assert response.context["f_category"] == "coverage_gap"


def test_explore_describes_configured_setting_search(client):
    page = client.get("/explore").text
    assert "Estate-wide search across configured settings." in page
    assert "search across GPOs, OUs" not in page


def test_duplicate_analysis_warning_is_visible_and_exported(client):
    import sqlite3

    from gpo_lens.findings import candidates_from_estate, create_evaluation_run, run_evaluation
    from gpo_lens.ingest import load_estate
    from gpo_lens.store import save_estate

    with closing(sqlite3.connect(client.app.state.db_path)) as conn, conn:
        estate = load_estate(ROOT / "tests/fixtures")
        sid = save_estate(conn, estate)
        candidate = candidates_from_estate(estate, snapshot_id=sid)[0]
        run_evaluation(conn, create_evaluation_run(conn, sid), [candidate, candidate])
    page = client.get("/findings")
    assert 'role="alert"' in page.text
    assert "Degraded analysis: 1 duplicate fingerprint" in page.text
    assert "Degraded analysis: 1 duplicate fingerprint" in client.get("/findings?format=csv").text
