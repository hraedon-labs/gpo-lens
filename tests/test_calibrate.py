"""Calibration runs use synthetic fixtures; no sample discovery is permitted."""

from __future__ import annotations

import copy
import importlib.util
import json
import logging
import sqlite3
import sys
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "calibrate_harness", ROOT / "scripts" / "calibrate.py"
)
assert SPEC and SPEC.loader
calibrate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = calibrate
SPEC.loader.exec_module(calibrate)


@pytest.fixture
def fixture_zip(tmp_path: Path) -> Path:
    archive = tmp_path / "synthetic.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        for path in sorted((ROOT / "tests" / "fixtures").rglob("*")):
            if path.is_file():
                zipped.write(path, path.relative_to(ROOT / "tests" / "fixtures"))
    return archive


@pytest.fixture
def fixture_run(tmp_path: Path, fixture_zip: Path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    with calibrate.private_output(calibrate.Capture(calibrate.source_formats())):
        report, denylist = calibrate.calibrate([fixture_zip, fixture_zip], scratch)
    return report, denylist, scratch


def test_fixture_report_shape_order_and_diff(fixture_run) -> None:
    report, denylist, scratch = fixture_run
    assert report["schema_version"] == 1
    assert [r["export_index"] for r in report["ingest"]] == [0, 1]
    assert [r["snapshot_id"] for r in report["ingest"]] == [1, 2]
    assert all(r["exit_status"] == 0 for r in report["ingest"])
    counts = report["ingest"][0]["counts"]
    assert counts["gpos"] == 14
    assert counts["settings"] > 0
    assert counts["soms"] > 0
    assert counts["settings_by_source_state"]["normal"] > 0
    assert report["diffs"][0]["diff"]["gpos_added"] == 0
    assert report["diffs"][0]["diff-settings"]["modified"] == 0
    assert report["determinism"]["identical"] is True
    assert report["determinism"]["fingerprints_added"] == 0
    assert all(r["exit_status"] == 0 for r in report["commands"])
    assert {"doctor", "danger", "admx-gaps", "broken-refs", "topology-check", "changelog"} <= {
        r["name"] for r in report["commands"]
    }
    assert report["redaction"]["detected_by_class"]["cpassword"] == 1
    assert report["scale"]["db_bytes"] > 0
    assert 0 < len(report["scale"]["slowest_routes"]) <= 10
    assert "gpo-cpassword" in denylist
    assert (scratch / "estate.sqlite3").exists()
    assert report["scale"]["db_bytes"] == (scratch / "estate.sqlite3").stat().st_size
    with sqlite3.connect(scratch / "estate.sqlite3") as conn:
        assert conn.execute("SELECT COUNT(*) FROM snapshot").fetchone()[0] == 2


def test_routes_are_enumerated_and_exports_render(fixture_run) -> None:
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    report, _, scratch = fixture_run
    with TestClient(create_app(str(scratch / "estate.sqlite3"))):
        app = create_app(str(scratch / "estate.sqlite3"))
    expected = {r.path for r in app.routes}
    actual = {r["route_template"] for r in report["web"]}
    assert actual == expected
    assert not report["web_5xx"]
    successful_exports = [r for r in report["web"] if r["format"] and r["status_code"] == 200]
    assert {r["format"] for r in successful_exports} == {"json", "md", "csv"}
    assert all(r["response_bytes"] > 0 and r["row_count"] >= 0 for r in successful_exports)
    assert all(r["wall_seconds"] >= 0 for r in report["web"])
    assert not any(r["status_code"] in {401, 403, 429} for r in report["web"])


def homelab_style_zip(tmp_path: Path) -> Path:
    """Windows path separators, wrapper directory, BOM JSON and unknown CSE."""
    archive = tmp_path / "synthetic-homelab.zip"
    report = (ROOT / "tests" / "fixtures" / "AllGPOs.xml").read_text()
    report = report.replace(
        "<Name>Registry</Name>", "<Name>PRIVATE-SYNTHETIC-EXTENSION</Name>", 1
    ).replace("<Extension>", '<Extension guid="{98765432-1234-5678-90ab-123456789abc}">', 1)
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("wrapped\\", b"")
        zipped.writestr("wrapped\\AllGPOs.xml", report)
        zipped.writestr("wrapped\\gp-inheritance.json", b"\xef\xbb\xbf[]")
        zipped.writestr("wrapped\\gpo-metadata.json", '["PRIVATE-SYNTHETIC-WARNING"]')
        zipped.writestr(
            "wrapped\\secrets.xml",
            '<secret password="SYNTHETIC-PASSWORD-CALIBRATION">'
            '<Properties hive="HKLM" key="Software\\Synthetic" name="DefaultPassword" '
            'value="SYNTHETIC-REGISTRY-CALIBRATION"/>'
            "<password>SYNTHETIC-TAG-CALIBRATION</password>"
            "<Url>https://user:SYNTHETIC-URI-CALIBRATION@synthetic.example.test</Url>"
            "</secret>",
        )
    return archive


def test_homelab_style_unknown_identifiers_never_project(tmp_path: Path) -> None:
    archive = homelab_style_zip(tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    with calibrate.private_output(calibrate.Capture(calibrate.source_formats())):
        report, denylist = calibrate.calibrate([archive], scratch)
    assert report["ingest"][0]["exit_status"] == 0
    counts = report["ingest"][0]["counts"]
    assert counts["extensions"]["unknown_guid_count"] == 1
    assert counts["settings_by_cse"]["other_count"] > 0
    serialized = json.dumps(report)
    for value in (
        "{98765432-1234-5678-90ab-123456789abc}",
        "PRIVATE-SYNTHETIC-EXTENSION",
        "PRIVATE-SYNTHETIC-WARNING",
        "SYNTHETIC-PASSWORD-CALIBRATION",
        "SYNTHETIC-REGISTRY-CALIBRATION",
        "SYNTHETIC-URI-CALIBRATION",
        "SYNTHETIC-TAG-CALIBRATION",
    ):
        assert value.strip("{}") not in serialized
    classes = report["redaction"]["detected_by_class"]
    assert classes["registry_credential"] >= 1
    assert classes["uri_userinfo"] >= 1
    assert classes["credential_field"] >= 1
    calibrate.self_check(report, denylist)
    mutated = copy.deepcopy(report)
    mutated["ingest"][0]["planted"] = "PRIVATE-SYNTHETIC-EXTENSION"
    with pytest.raises(calibrate.SanitizationError):
        calibrate.self_check(mutated, denylist)


@pytest.mark.parametrize(
    "planted",
    [
        {"payload": "GPO-CPASSWORD"},
        {"payload": "prefix-gpo-cpassword-suffix"},
        {"payload": ["gpo-cpassword"]},
        {"payload": "leak-\u00e9xample"},
    ],
)
def test_self_check_blocks_planted_leak(planted) -> None:
    with pytest.raises(calibrate.SanitizationError) as caught:
        calibrate.self_check(planted, {"gpo-cpassword", "\u00c9XAMPLE", "1234"})
    assert caught.value.field.startswith("$")
    assert "gpo-cpassword" not in str(caught.value).lower()
    assert "xample" not in str(caught.value).lower()


def test_self_check_uses_nested_database_text_and_export_paths(tmp_path: Path) -> None:
    with sqlite3.connect(":memory:") as conn:
        conn.execute("CREATE TABLE data (number INTEGER, text TEXT, blob TEXT)")
        conn.execute(
            "INSERT INTO data VALUES (?, ?, ?)",
            (1, "SYNTHETIC-DB-NAME", json.dumps({"value": "SYNTHETIC-NESTED-VALUE"})),
        )
        denylist = calibrate.database_strings(conn)
    assert "SYNTHETIC-DB-NAME" in denylist
    assert "SYNTHETIC-NESTED-VALUE" in denylist
    facts = calibrate.InputFacts()
    dest = tmp_path / "extracted"
    calibrate.read_input(homelab_style_zip(tmp_path), dest, facts)
    assert "wrapped" in facts.denylist
    assert "PRIVATE-SYNTHETIC-EXTENSION" in facts.denylist
    for value in ("SYNTHETIC-NESTED-VALUE", "PRIVATE-SYNTHETIC-EXTENSION", "wrapped"):
        with pytest.raises(calibrate.SanitizationError):
            calibrate.self_check({"payload": value}, denylist | facts.denylist)


def test_self_check_mutation_is_killed() -> None:
    """The planted-leak assertion fails if the gate's denylist is disabled."""
    source = (ROOT / "scripts" / "calibrate.py").read_text()
    start = source.index("def self_check(")
    end = source.index("\n\n@dataclasses.dataclass", start)
    function = source[start:end].replace(
        "needles = {s.casefold() for s in denylist if len(s) >= 4}",
        "needles: set[str] = set()",
    )
    namespace = dict(vars(calibrate))
    exec(compile(function, "<gate-mutant>", "exec"), namespace)  # noqa: S102

    def planted_leak_assertion(module: ModuleType | dict) -> None:
        gate = module["self_check"] if isinstance(module, dict) else module.self_check
        with pytest.raises(calibrate.SanitizationError):
            gate({"payload": "synthetic-private-value"}, {"synthetic-private-value"})

    planted_leak_assertion(calibrate)
    with pytest.raises(pytest.fail.Exception):
        planted_leak_assertion(namespace)


def test_unknown_warning_and_logs_are_counts_only(capsys) -> None:
    capture = calibrate.Capture(calibrate.source_formats())
    with calibrate.private_output(capture):
        logging.warning("PRIVATE-SYNTHETIC-MESSAGE \\server\\path SECRET")
        import warnings

        warnings.warn("PRIVATE-SYNTHETIC-MESSAGE", stacklevel=1)
        warnings.warn(
            "Unexpected top-level str in /private/domain.example.test/input.json; "
            "expected object or array",
            stacklevel=1,
        )
        print("PRIVATE-SYNTHETIC-STDOUT")
        print("PRIVATE-SYNTHETIC-STDERR", file=sys.stderr)
    assert not capsys.readouterr().out
    assert not capsys.readouterr().err
    report = capture.report()
    assert report["other_warnings"] == 2
    assert sum(report["templates"].values()) == 1
    assert "PRIVATE-SYNTHETIC" not in json.dumps(report)
    assert "domain.example.test" not in json.dumps(report)


def test_exception_messages_never_emit_and_own_source_only() -> None:
    from gpo_lens.ingest import load_estate

    try:
        load_estate("/PRIVATE-SYNTHETIC-NONEXISTENT")
    except FileNotFoundError as exc:
        info = calibrate.exception_info(exc)
    assert info["class"] == "FileNotFoundError"
    assert info["source"][0].startswith("gpo_lens/ingest.py:")
    assert "PRIVATE-SYNTHETIC" not in json.dumps(info)


@pytest.mark.parametrize("value", ["SYNTHETIC-SECRET", "a<&|`secret", "secret with spaces"])
def test_secret_comparison_decodes_html_json_and_uri(value: str) -> None:
    import html
    from urllib.parse import quote

    assert calibrate.leak_count(html.escape(value), {value}) == 1
    assert calibrate.leak_count(json.dumps({"value": value}), {value}) == 1
    assert calibrate.leak_count(quote(value), {value}) == 1
    assert calibrate.leak_count("[REDACTED]", {value}) == 0


@pytest.mark.parametrize("entry", ["../escape.xml", "/escape.xml", "..\\escape.xml"])
def test_archive_paths_cannot_escape(tmp_path: Path, entry: str) -> None:
    archive = tmp_path / "invalid.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr(entry, "PRIVATE-SYNTHETIC")
    with pytest.raises(ValueError):
        calibrate.read_input(archive, tmp_path / "dest", calibrate.InputFacts())
    assert not (tmp_path / "escape.xml").exists()


def test_literal_gate_exempts_source_identifier_collisions(fixture_run) -> None:
    report, denylist, _ = fixture_run
    assert "normal" in denylist
    assert json.loads(calibrate.self_check(report, denylist)) == report
    mutated = copy.deepcopy(report)
    mutated["analysis"][0]["planted"] = "gpo-cpassword"
    with pytest.raises(calibrate.SanitizationError):
        calibrate.self_check(mutated, denylist)


def test_gate_exemptions_are_exact_and_independent_of_data() -> None:
    allowed = calibrate.own_vocabulary()
    assert {"normal", "blocked", "inaccessible", "confirmed", "doctor", "/gpo/{gpo_id}"} <= allowed
    assert "gpo-cpassword" not in allowed
    report = {"gpo-cpassword": [False, 12345678, "normal", "doctor"]}
    assert (
        json.loads(
            calibrate.self_check(report, {"gpo-cpassword", "1234", "false", "normal", "doctor"})
        )
        == report
    )
    for value in ("prefix-normal-suffix", "NORMAL", "some-doctor"):
        with pytest.raises(calibrate.SanitizationError):
            calibrate.self_check({"value": value}, {"normal", "doctor"})


def test_main_refusal_blocks_report_preserves_requested_db_and_cleans_scratch(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    output = tmp_path / "report.json"
    keep = tmp_path / "keep.sqlite3"
    scratch_seen = []

    def planted(archives, scratch):
        scratch_seen.append(scratch)
        (scratch / "estate.sqlite3").write_bytes(b"PRIVATE-SYNTHETIC")
        return {"field": "PRIVATE-SYNTHETIC"}, {"PRIVATE-SYNTHETIC"}

    monkeypatch.setattr(calibrate, "calibrate", planted)
    status = calibrate.main(["--out", str(output), "--keep-db", str(keep), "private.zip"])
    assert status == 2
    assert not output.exists()
    assert keep.read_bytes() == b"PRIVATE-SYNTHETIC"
    assert not scratch_seen[0].exists()
    out = capsys.readouterr()
    assert not out.out
    assert out.err == "Sanitization refused at $[0]\n"


def test_report_projection_does_not_contain_fixture_identifiers(fixture_run) -> None:
    report, _, _ = fixture_run
    # Independently check identifiers as well as the mechanically exempted gate.
    serialized = json.dumps(report).casefold()
    with sqlite3.connect(fixture_run[2] / "estate.sqlite3") as conn:
        for query in (
            "SELECT name FROM gpo",
            "SELECT path FROM som",
            "SELECT sysvol_path FROM gpo",
        ):
            for (value,) in conn.execute(query):
                if value and len(value) >= 4:
                    assert value.casefold() not in serialized
    mutated = copy.deepcopy(report)
    mutated["analysis"][0]["planted"] = "gpo-cpassword"
    with pytest.raises(calibrate.SanitizationError):
        calibrate.self_check(mutated, {"gpo-cpassword"})


def test_cli_failure_has_status_and_sanitized_exception(tmp_path: Path) -> None:
    payload, record = calibrate.run_command(
        tmp_path / "PRIVATE-SYNTHETIC-NONEXISTENT.sqlite3", "doctor", [], calibrate.source_formats()
    )
    assert payload is None
    assert record["exit_status"] != 0
    assert record["exceptions"]
    assert "PRIVATE-SYNTHETIC" not in json.dumps(record)


def test_web_probe_counts_planted_response_leak_and_crash(fixture_run, monkeypatch) -> None:
    from gpo_lens.store import load_estate
    from gpo_lens.web import app as web_app

    _, _, scratch = fixture_run
    original = web_app.create_app
    secret = "SYNTHETIC-HTML-LEAK-CALIBRATION"

    def instrumented(*args, **kwargs):
        app = original(*args, **kwargs)

        @app.get("/calibration-leak")
        def leaked():
            return {"value": secret}

        @app.get("/calibration-crash")
        def crashed():
            raise RuntimeError(secret)

        @app.get("/calibration-logged-crash")
        def logged_crash():
            from fastapi.responses import JSONResponse

            try:
                raise RuntimeError(secret)
            except RuntimeError:
                logging.exception("Synthetic caught API failure")
                return JSONResponse({"error": "internal error"}, status_code=500)

        return app

    monkeypatch.setattr(web_app, "create_app", instrumented)
    with sqlite3.connect(scratch / "estate.sqlite3") as conn:
        estate = load_estate(conn)
    detail = calibrate.Detail()
    token = calibrate.DETAIL.set(detail)
    try:
        with calibrate.private_output(calibrate.Capture(calibrate.source_formats())):
            records, leaks = calibrate.web_probe(
                scratch / "estate.sqlite3",
                estate,
                scratch.parent / "synthetic.zip",
                calibrate.source_formats(),
                {secret},
                scratch / "PolicyDefinitions",
            )
    finally:
        calibrate.DETAIL.reset(token)
    assert leaks["/calibration-leak"] == 1
    crash = next(r for r in records if r["route_template"] == "/calibration-crash")
    assert crash["status_code"] == 500
    assert crash["exceptions"][0]["class"] == "RuntimeError"
    assert secret not in json.dumps([records, leaks])
    categories = detail.report()["categories"]
    assert {"route": "/calibration-leak", "field": "$.value"} in categories["redaction_leaks"]
    assert secret not in json.dumps(categories["redaction_leaks"])
    failure = next(r for r in categories["web_5xx"] if r["route"] == "/calibration-crash")
    assert failure["exceptions"][0]["message"] == secret
    assert all(
        frame["file"].startswith("gpo_lens/") for frame in failure["exceptions"][0]["traceback"]
    )
    assert len(categories["slowest_routes"]) == 10
    logged = next(r for r in categories["web_5xx"] if r["route"] == "/calibration-logged-crash")
    assert logged["exceptions"][0]["message"] == secret
    assert all(
        frame["file"].startswith("gpo_lens/") for frame in logged["exceptions"][0]["traceback"]
    )


def test_duplicate_fingerprint_signal_is_measured(fixture_zip, tmp_path: Path, monkeypatch) -> None:
    from gpo_lens import findings

    original = findings.candidates_from_estate

    def duplicated(*args, **kwargs):
        candidates = original(*args, **kwargs)
        return candidates + candidates[:1]

    monkeypatch.setattr(findings, "candidates_from_estate", duplicated)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    with calibrate.private_output(calibrate.Capture(calibrate.source_formats())):
        report, _ = calibrate.calibrate([fixture_zip], scratch)
    runs = [r for r in report["commands"] if "duplicate_fingerprint_count" in r]
    assert runs[0]["duplicate_fingerprint_count"] == 1
    assert runs[0]["degraded_analysis"] is True
    assert "colliding candidates" not in json.dumps(report)


def test_main_atomic_output_keep_db_and_model_isolation(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    import os

    output = tmp_path / "report.json"
    keep = tmp_path / "keep.sqlite3"
    monkeypatch.setenv("GPO_LENS_API_KEY", "SYNTHETIC-CONFIG-CALIBRATION")
    seen = []

    def harmless(archives, scratch):
        assert "GPO_LENS_API_KEY" not in os.environ
        seen.append(scratch)
        (scratch / "estate.sqlite3").write_bytes(b"synthetic-database")
        return {
            "ingest": [{"exit_status": 0, "counts": {"gpos": 0, "soms": 0, "settings": 0}}],
            "web": [],
            "web_5xx": [],
            "redaction": {},
            "determinism": {"identical": True},
            "scale": {"db_bytes": 18},
        }, {"PRIVATE-SYNTHETIC"}

    monkeypatch.setattr(calibrate, "calibrate", harmless)
    assert calibrate.main(["--out", str(output), "--keep-db", str(keep), "private.zip"]) == 0
    assert json.loads(output.read_text())["determinism"]["identical"] is True
    assert keep.read_bytes() == b"synthetic-database"
    assert not seen[0].exists()
    assert os.environ["GPO_LENS_API_KEY"] == "SYNTHETIC-CONFIG-CALIBRATION"
    assert "PRIVATE-SYNTHETIC" not in capsys.readouterr().out


def test_output_cannot_replace_input(tmp_path: Path, capsys) -> None:
    archive = tmp_path / "private.zip"
    archive.write_bytes(b"synthetic-input")
    assert calibrate.main(["--out", str(archive), str(archive)]) == 1
    assert archive.read_bytes() == b"synthetic-input"
    assert "private.zip" not in capsys.readouterr().err


@pytest.mark.parametrize("symlink", [False, True])
def test_detail_output_refuses_worktree_before_ingest(tmp_path, monkeypatch, capsys, symlink):
    destination = ROOT / "private-calibration-detail.json"
    if symlink:
        link = tmp_path / "repo-link"
        link.symlink_to(ROOT, target_is_directory=True)
        destination = link / "private-calibration-detail.json"

    def forbidden(*args):
        pytest.fail("guard must refuse before opening any input")

    monkeypatch.setattr(calibrate, "calibrate", forbidden)
    assert (
        calibrate.main(
            [
                "--out",
                str(tmp_path / "report.json"),
                "--detail",
                "--detail-out",
                str(destination),
                "unused.zip",
            ]
        )
        == 1
    )
    assert not destination.exists()
    out = capsys.readouterr()
    assert not out.out
    assert "private-calibration-detail" not in out.err


def test_detail_guard_refuses_another_git_repo(tmp_path):
    import subprocess

    repo = tmp_path / "another-repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    with pytest.raises(ValueError):
        calibrate.detail_destination(repo / "nested" / "detail.json")
    assert calibrate.detail_destination(tmp_path / "private" / "detail.json").is_absolute()


@pytest.mark.parametrize(
    "options",
    [
        ["--detail"],
        ["--detail-out", "outside.json"],
    ],
)
def test_detail_flags_must_be_paired(tmp_path, monkeypatch, options):
    monkeypatch.setattr(calibrate, "calibrate", lambda *args: pytest.fail("must refuse first"))
    assert calibrate.main(["--out", str(tmp_path / "report.json"), *options, "unused.zip"]) == 1


def test_detail_output_cannot_alias_sanitized_report(tmp_path, monkeypatch):
    output = tmp_path / "report.json"
    monkeypatch.setattr(calibrate, "calibrate", lambda *args: pytest.fail("must refuse first"))
    assert (
        calibrate.main(
            [
                "--out",
                str(output),
                "--detail",
                "--detail-out",
                str(output),
                "unused.zip",
            ]
        )
        == 1
    )
    assert not output.exists()


def test_detail_warning_templates_examples_and_caps():
    detail = calibrate.Detail()
    for index in range(20):
        detail.warning(
            f"Unexpected top-level str in /synthetic/domain-{index}.test/input.json; "
            "expected object or array"
        )
        detail.add("admx_gaps", {"key_path": f"Software\\Synthetic\\{index}"})
    rows = detail.report()["categories"]["warnings"]
    assert len(rows) == 1
    assert (
        rows[0]["template"] == "Unexpected top-level <value> in <value>; expected object or array"
    )
    assert len(rows[0]["examples"]) == 3
    assert "/synthetic/domain-0.test/input.json" in rows[0]["examples"][0]
    assert len(detail.report()["categories"]["admx_gaps"]) == 10


def test_detail_real_pipeline_separate_from_sanitized_report(tmp_path, capsys):
    archive = homelab_style_zip(tmp_path)
    output = tmp_path / "report.json"
    private = tmp_path / "detail.json"
    assert (
        calibrate.main(
            [
                "--out",
                str(output),
                "--detail",
                "--detail-out",
                str(private),
                str(archive),
            ]
        )
        == 0
    )
    detail = json.loads(private.read_text())
    assert "CONTAINS ESTATE DATA" in detail["label"]
    categories = detail["categories"]
    assert all(len(rows) <= 10 for rows in categories.values())
    assert all(len(r["examples"]) <= 3 for r in categories["warnings"])
    extensions = categories["extensions"]
    unknown = "{98765432-1234-5678-90ab-123456789abc}"
    assert any(unknown.strip("{}") in r.get("guids", []) for r in extensions)
    assert any(r.get("element_names") for r in extensions)
    assert categories["blocked_or_unparsed_settings"]
    assert categories["admx_gaps"]
    assert categories["skipped_content"]
    assert categories["slowest_routes"]
    assert all(r["url"].startswith("/") for r in categories["slowest_routes"])
    assert "PRIVATE-SYNTHETIC-EXTENSION" in private.read_text()
    assert "PRIVATE-SYNTHETIC" not in output.read_text()
    assert "PRIVATE-SYNTHETIC" not in capsys.readouterr().out
    assert calibrate.DETAIL.get() is None


def test_detail_leak_locations_omit_values_even_in_keys():
    secret = "SYNTHETIC-SECRET-CALIBRATION"
    body = json.dumps({"outer": [{"value": secret}], secret: "safe"})
    fields = calibrate.leak_fields(body, {secret}, "json")
    assert "$.outer[0].value" in fields
    assert "$[key:1]" in fields
    assert secret not in json.dumps(fields)
    assert calibrate.leak_fields(f"<p>{secret}</p>", {secret}, "") == ["response.body"]


@pytest.mark.parametrize(
    "cse, block",
    [
        (
            "Registry",
            '<RegistrySettings><Registry><Properties hive="HKLM" key="Software\\Synthetic" '
            'name="Valid" value="1"/></Registry><Registry><Properties name="Dropped" value="2"/>'
            "</Registry></RegistrySettings>",
        ),
        (
            "Drive Maps",
            '<Drives clsid="synthetic-container"><Drive uid="synthetic-item" name="Valid">'
            '<Properties path="synthetic-path"/></Drive><Drive name="Dropped">'
            '<Properties path="synthetic-other-path"/></Drive></Drives>',
        ),
    ],
)
def test_detail_captures_mixed_gpp_skips(cse, block):
    from gpo_lens import ingest

    element = calibrate.ET.fromstring(
        f"<GPO><Computer><Enabled>true</Enabled><ExtensionData><Name>{cse}</Name>"
        f"<Extension>{block}</Extension></ExtensionData></Computer></GPO>"
    )
    detail = calibrate.Detail()
    token = calibrate.DETAIL.set(detail)
    try:
        with calibrate.detail_ingest():
            settings = ingest._parse_settings(element, "synthetic-gpo-id")
    finally:
        calibrate.DETAIL.reset(token)
    assert len(settings) == 1
    assert settings[0].display_name == "Valid"
    rows = detail.report()["categories"]["skipped_content"]
    assert len(rows) == 1
    assert rows[0]["extension"] == cse
    assert rows[0]["side"] == "Computer"
    assert "Dropped" in rows[0]["setting_names"]
    assert "not emitted" in rows[0]["reason"]
