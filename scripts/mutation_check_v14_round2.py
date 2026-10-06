"""Require the round-2 regressions to reject deliberately restored defects.

Mutations run in temporary copies of src/scripts/tests; the worktree is never
mutated. Run the full release gates afterward, on the final unmodified source.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parent.parent
ATOMIC = "tests/test_review_atomic_ingest.py"
BASELINE = "tests/test_review_baseline.py"
PROVENANCE = "tests/test_review_provenance.py"
STORE = "src/gpo_lens/store.py"
WEB = "src/gpo_lens/web/routes/ingest.py"

# name, file, exact replacement, replacement, regression (pytest node or Pester)
MUTATIONS = (
    (
        "F-02 web audit commits early",
        WEB,
        '{"principal": principal.name},\n                            commit=False,',
        '{"principal": principal.name},\n                            commit=True,',
        ATOMIC + "::test_ingest_event_failure_rolls_back_even_after_event_insert[web]",
    ),
    (
        "F-02 CLI snapshot commits early",
        "src/gpo_lens/cli/_estate.py",
        "conn, estate, admx=_get_admx(args), commit=False",
        "conn, estate, admx=_get_admx(args), commit=True",
        ATOMIC + "::test_ingest_event_failure_rolls_back_even_after_event_insert[cli]",
    ),
    (
        "F-02 deletion commits early",
        WEB,
        "_store.delete_snapshot(rw_conn, snapshot_id, commit=False)",
        "_store.delete_snapshot(rw_conn, snapshot_id, commit=True)",
        ATOMIC + "::test_snapshot_delete_audit_failure_rolls_back",
    ),
    (
        "F-03 baseline includes disabled values",
        "src/gpo_lens/queries/_baseline.py",
        's.source_state == "blocked" or s.from_disabled_side',
        's.source_state == "blocked"',
        BASELINE + "::test_baseline_disabled_side_cannot_supply_compliance",
    ),
    (
        "F-03 golden includes disabled values",
        "src/gpo_lens/queries/_golden.py",
        's.source_state == "blocked" or s.from_disabled_side',
        's.source_state == "blocked"',
        BASELINE + "::test_golden_disabled_side_is_absent_in_both_directions",
    ),
    (
        "F-11 global short/numeric substring masking",
        "src/gpo_lens/safe_output.py",
        "if substring_mask:",
        "if True:",
        "tests/test_review_output_safety.py::test_short_secret_does_not_corrupt_dates_identifiers_or_counts",
    ),
    (
        "F-10 observations discard detector version",
        "src/gpo_lens/findings.py",
        "                        cand.gpo_name,\n                        cand.detector_version,",
        "                        cand.gpo_name,\n                        None,",
        PROVENANCE
        + "::test_detector_version_provenance_with_triage_continuity[observation_versions]",
    ),
    (
        "F-10 ingest omits application version",
        STORE,
        "application_version=__version__, commit=False",
        'application_version="", commit=False',
        ATOMIC + "::test_normal_ingest_records_application_version",
    ),
    (
        "F-10 missing observation migration",
        STORE,
        'if not _column_exists(conn, "finding_observation", "detector_version"):',
        "if False:",
        "tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity",
    ),
    (
        "F-10 ID-only digest",
        "src/gpo_lens/findings.py",
        "sorted(INTRINSIC_DETECTOR_VERSIONS.items())",
        "sorted(INTRINSIC_DETECTOR_VERSIONS)",
        PROVENANCE + "::test_detector_version_provenance_with_triage_continuity[digest]",
    ),
    (
        "F-05 registration accepts another owner",
        "scripts/Register-GpoLensCollection.ps1",
        "if (-not $Force) { throw",
        "if ($false) { throw",
        "pester",
    ),
    (
        "F-05 runner ignores owner",
        "scripts/Run-GpoLensCollection.ps1",
        "    Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName",
        "    # MUTANT: ignore ownership",
        "pester",
    ),
    (
        "F-05 task action drops owner name",
        "scripts/Register-GpoLensCollection.ps1",
        "        ' -TaskName ' + (ConvertTo-GpoLensTaskArgument $TaskName) +\n",
        "",
        "pester",
    ),
    (
        "F-02 web commits before temporary cleanup",
        WEB,
        "with rw_conn, temporary:",
        "with temporary, rw_conn:",
        ATOMIC + "::test_ingest_temporary_cleanup_failure_rolls_back[web]",
    ),
    (
        "F-02 CLI commits before temporary cleanup",
        "src/gpo_lens/cli/_estate.py",
        "conn, estate, admx=_get_admx(args), commit=False",
        "conn, estate, admx=_get_admx(args), commit=True",
        ATOMIC + "::test_ingest_temporary_cleanup_failure_rolls_back[cli]",
    ),
    (
        "F-05 failed takeover does not restore the owner",
        "scripts/Register-GpoLensCollection.ps1",
        "if ($null -ne $previousBytes) { [IO.File]::WriteAllBytes($marker, $previousBytes) }",
        "if ($false) { [IO.File]::WriteAllBytes($marker, $previousBytes) }",
        "pester",
    ),
    (
        "F-11 escaped short values use rendered length",
        "src/gpo_lens/safe_output.py",
        "if substring_mask:",
        "if len(secret) >= 6 and not secret.isnumeric():",
        "tests/test_review_output_safety.py::test_short_secret_keeps_token_policy_after_html_escaping",
    ),
    (
        "F-10 rule content omitted from digest",
        "src/gpo_lens/findings.py",
        '"rules": [dataclasses.asdict(rule) for rule in sorted(rules, key=lambda r: r.id)],',
        '"rules": [],',
        PROVENANCE + "::test_pipeline_digest_records_checks_with_no_findings[rule_content]",
    ),
    (
        "F-11 short variant suppresses a real long credential",
        "src/gpo_lens/safe_output.py",
        "variants.get(variant, False) or substring_mask",
        "variants.get(variant, True) and substring_mask",
        "tests/test_review_output_safety.py::test_escaped_variant_collision_keeps_long_secret_substring_masking",
    ),
)


def main() -> int:
    survivors = []
    for name, file, old, new, regression in MUTATIONS:
        with TemporaryDirectory(prefix="gpo-v14-mutant-") as directory:
            sandbox = Path(directory)
            shutil.copytree(
                ROOT / "src", sandbox / "src", ignore=shutil.ignore_patterns("__pycache__")
            )
            if regression == "pester":
                shutil.copytree(ROOT / "scripts", sandbox / "scripts")
                tests = sandbox / "tests/powershell"
                tests.mkdir(parents=True)
                shutil.copyfile(
                    ROOT / "tests/powershell/collection.Tests.ps1", tests / "collection.Tests.ps1"
                )
                command = [
                    "pwsh",
                    "-NoProfile",
                    "-Command",
                    "$r=Invoke-Pester -Path tests/powershell/collection.Tests.ps1 "
                    "-Output Detailed -PassThru; if ($r.FailedCount -gt 0) { exit 1 }",
                ]
            else:
                command = [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-o",
                    "addopts=",
                    "-q",
                    str(ROOT / regression),
                ]
            target = sandbox / file
            source = target.read_text()
            if old not in source:
                raise RuntimeError(f"Mutation anchor disappeared: {name}")
            target.write_text(source.replace(old, new))
            env = {**os.environ, "PYTHONPATH": str(sandbox / "src")}
            result = subprocess.run(
                command, cwd=sandbox, env=env, text=True, capture_output=True, check=False
            )
            # A collection/import error is not a killed mutant. Require a test
            # assertion failure and preserve the output for examination.
            output = result.stdout + result.stderr
            killed = result.returncode == 1 and (
                ("AssertionError" in output and "FAILED " in output)
                if regression != "pester"
                else "[-]" in output and "Expected" in output
            )
            print(f"{'KILLED' if killed else 'SURVIVED'}: {name}", flush=True)
            print(output, flush=True)
            if not killed:
                survivors.append(name)
    print(f"Mutation proof: {len(MUTATIONS) - len(survivors)}/{len(MUTATIONS)} killed")
    return int(bool(survivors))


if __name__ == "__main__":
    raise SystemExit(main())
